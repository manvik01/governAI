"""Sample agent 3: model calls routed through LiteLLM, logged by the ZenAi4 callback.

Uses LiteLLM's mock responses, so no provider key or cost; LiteLLM still builds
its full standard logging payload (model, tokens, cost, key alias) and the
callback posts it to the intake. One call per run fails on purpose, so the
failure path is captured too.

    ZENAI4_LITELLM_TOKEN=... ZENAI4_INTAKE_URL=http://127.0.0.1:8788 python agent_litellm.py [runs]
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "litellm"))

import litellm  # noqa: E402
import zenai4_callback  # noqa: E402

litellm.callbacks = [zenai4_callback.ZenAi4Logger()]

if __name__ == "__main__":
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    for i in range(runs):
        r = litellm.completion(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": f"Summarise ticket T-{3000 + i} for jane@example.com"}],
            mock_response="Ticket summarised.",
            metadata={"user_api_key_alias": "ticket-summariser", "user_api_key_user_id": "jane@example.com"},
        )
        print(r.choices[0].message.content)
    try:
        litellm.completion(model="gpt-4o-mini", messages=[{"role": "user", "content": "x"}], mock_response=Exception("mock rate limit"), num_retries=0)
    except Exception:  # noqa: BLE001
        print("failure call logged")
    time.sleep(1)  # let the callback finish posting
