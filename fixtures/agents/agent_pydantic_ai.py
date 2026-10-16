"""Sample agent 1: emits OpenTelemetry GenAI spans natively (Pydantic AI).

A refund agent with one tool. Uses Pydantic AI's built-in instrumentation, so
the spans are exactly what a customer's Pydantic AI agent would send. The model
is the fake OpenAI-compatible server, so runs are free and repeatable.

    ZENAI4_SOURCE_TOKEN=... FAKE_LLM_URL=http://127.0.0.1:18080/v1 [ZENAI4_PAI_VERSION=2..6] python agent_pydantic_ai.py [runs]
"""

import os
import sys

from common import setup_tracing

provider = setup_tracing("refund-bot", "pydantic-ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models.instrumented import InstrumentationSettings  # noqa: E402
from pydantic_ai.models.openai import OpenAIChatModel  # noqa: E402
from pydantic_ai.providers.openai import OpenAIProvider  # noqa: E402

model = OpenAIChatModel("gpt-4o-mini", provider=OpenAIProvider(base_url=os.environ.get("FAKE_LLM_URL", "http://127.0.0.1:18080/v1"), api_key="fake"))
# Content capture is ON here on purpose: it proves ZenAi4 drops prompts and outputs at intake.
# ZENAI4_PAI_VERSION picks Pydantic AI's instrumentation version (2-6), i.e. which
# generation of the OpenTelemetry GenAI conventions the spans follow.
Agent.instrument_all(InstrumentationSettings(tracer_provider=provider, include_content=True, version=int(os.environ.get("ZENAI4_PAI_VERSION", "5"))))
agent = Agent(model, name="refund-bot", instructions="You process refunds for customer support.")


@agent.tool_plain
def lookup_order(order_id: str) -> str:
    """Look up an order by id."""
    return f"order {order_id}: S$80, delivered"


if __name__ == "__main__":
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    for i in range(runs):
        result = agent.run_sync(f"Customer asks for a refund on order A-{1000 + i}.")
        print(result.output)
    provider.shutdown()
