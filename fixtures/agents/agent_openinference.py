"""Sample agent 2: plain OpenAI SDK code, instrumented with OpenInference.

The pattern for custom agents that do not emit OpenTelemetry themselves: one
instrumentor call at start-up, no other code change. Calls the fake model
server through the OpenAI client and runs one tool by hand.

    ZENAI4_SOURCE_TOKEN=... FAKE_LLM_URL=http://127.0.0.1:18080/v1 python agent_openinference.py [runs]
"""

import json
import os
import sys

from common import setup_tracing

provider = setup_tracing("support-agent", "openinference-openai")

from openinference.instrumentation.openai import OpenAIInstrumentor  # noqa: E402
from openai import OpenAI  # noqa: E402
from opentelemetry import trace  # noqa: E402

OpenAIInstrumentor().instrument(tracer_provider=provider)
client = OpenAI(base_url=os.environ.get("FAKE_LLM_URL", "http://127.0.0.1:18080/v1"), api_key="fake")
tracer = trace.get_tracer("support-agent")
TOOLS = [{"type": "function", "function": {"name": "crm_lookup", "description": "Find a customer", "parameters": {"type": "object", "properties": {"order_id": {"type": "string"}}}}}]


def run(i: int) -> str:
    with tracer.start_as_current_span("support-agent.run", attributes={"openinference.span.kind": "AGENT", "agent.name": "support-agent"}):
        messages = [{"role": "user", "content": f"Where is order A-{2000 + i}?"}]
        first = client.chat.completions.create(model="gpt-4o-mini", messages=messages, tools=TOOLS)
        call = first.choices[0].message.tool_calls[0]
        with tracer.start_as_current_span("crm_lookup", attributes={"openinference.span.kind": "TOOL", "tool.name": call.function.name}):
            result = {"status": "shipped"}
        messages += [first.choices[0].message.model_dump(exclude_none=True), {"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)}]
        second = client.chat.completions.create(model="gpt-4o-mini", messages=messages)
        return second.choices[0].message.content or ""


if __name__ == "__main__":
    for i in range(int(sys.argv[1]) if len(sys.argv) > 1 else 1):
        print(run(i))
    provider.shutdown()
