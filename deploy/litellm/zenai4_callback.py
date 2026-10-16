"""ZenAi4 logging callback for LiteLLM (SDK or proxy).

Posts LiteLLM's standard logging payload for every call, success or failure, to
the ZenAi4 intake. Message and response content are removed here before
sending, and again at intake.

Proxy (config.yaml):

    litellm_settings:
      callbacks: zenai4_callback.proxy_handler_instance

    environment: ZENAI4_INTAKE_URL=http://zenai4:8788  ZENAI4_LITELLM_TOKEN=<source token>

SDK:

    import litellm, zenai4_callback
    litellm.callbacks = [zenai4_callback.proxy_handler_instance]

Sending never raises into LiteLLM: a failed post is retried a few times and then
dropped with a warning, so ZenAi4 can never break a model call.
"""

import json
import logging
import os
import threading
import time
import urllib.request

from litellm.integrations.custom_logger import CustomLogger

log = logging.getLogger("zenai4")
CONTENT_KEYS = {"messages", "response", "prompt", "completion", "input", "output"}


def _strip(value):
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in value.items() if k not in CONTENT_KEYS}
    if isinstance(value, list):
        return [_strip(v) for v in value]
    return value


class ZenAi4Logger(CustomLogger):
    def __init__(self, url=None, token=None, retries=3):
        super().__init__()
        self.url = (url or os.environ.get("ZENAI4_INTAKE_URL", "http://127.0.0.1:8788")).rstrip("/") + "/v1/intake/litellm"
        self.token = token or os.environ.get("ZENAI4_LITELLM_TOKEN", "")
        self.retries = retries

    def _post(self, payload):
        body = json.dumps(_strip(payload), default=str).encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={"content-type": "application/json", "authorization": f"Bearer {self.token}"})
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status == 200:
                        return True
            except Exception as err:  # noqa: BLE001 - never raise into LiteLLM
                last = err
                time.sleep(0.5 * (attempt + 1))
        log.warning("zenai4: could not deliver a LiteLLM log: %s", last)
        return False

    def _send(self, kwargs, ok):
        payload = kwargs.get("standard_logging_object") or {}
        if not payload:
            return
        payload = dict(payload)
        payload.setdefault("status", "success" if ok else "failure")
        self._post(payload)

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        self._send(kwargs, True)

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        self._send(kwargs, False)

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        threading.Thread(target=self._send, args=(kwargs, True), daemon=True).start()

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        threading.Thread(target=self._send, args=(kwargs, False), daemon=True).start()


proxy_handler_instance = ZenAi4Logger()
