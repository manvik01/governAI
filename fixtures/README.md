# Fixtures

- `agents/`: three sample agents for phase 1 (fake model server, no provider keys):
  - `agent_pydantic_ai.py`: native OpenTelemetry GenAI spans (Pydantic AI; `ZENAI4_PAI_VERSION` picks the convention generation)
  - `agent_openinference.py`: OpenAI SDK code instrumented with OpenInference
  - `agent_litellm.py`: calls through LiteLLM, logged by `deploy/litellm/zenai4_callback.py`
  - `fake_llm.py`: OpenAI-compatible server returning a tool call, then an answer, with token usage
- `traces/`: records as stored by intake (already redacted) from one run of each agent,
  named by framework and version. Phase 2 mapping tests read these; add a file whenever a
  framework or its instrumentation version changes.
- `load/load.mjs`: load and restart test generator (see docs/deployment/capture.md).

Run the agents:

```sh
python3 -m venv .venv && .venv/bin/pip install pydantic-ai-slim opentelemetry-sdk \
  opentelemetry-exporter-otlp-proto-http openinference-instrumentation-openai openai litellm
.venv/bin/python fixtures/agents/fake_llm.py 18080 &
export ZENAI4_OTLP_ENDPOINT=http://127.0.0.1:8788 ZENAI4_SOURCE_TOKEN=<otlp token> FAKE_LLM_URL=http://127.0.0.1:18080/v1
cd fixtures/agents && ../../.venv/bin/python agent_pydantic_ai.py 3
```
