"""Shared setup for the sample agents: OpenTelemetry export to ZenAi4.

Each agent sends to ZENAI4_OTLP_ENDPOINT (the Collector at :4318 on a VM, or the
intake directly in tests) with the source token in ZENAI4_SOURCE_TOKEN. Nothing
else in the agent changes: that is the "exporter settings only" promise.
"""

import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def setup_tracing(service_name: str, framework: str) -> TracerProvider:
    endpoint = os.environ.get("ZENAI4_OTLP_ENDPOINT", "http://127.0.0.1:4318").rstrip("/")
    token = os.environ["ZENAI4_SOURCE_TOKEN"]
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service_name,
                "deployment.environment": os.environ.get("ZENAI4_ENV", "fixture"),
                "zenai4.fixture.framework": framework,
            }
        )
    )
    provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces", headers={"authorization": f"Bearer {token}"})
        )
    )
    trace.set_tracer_provider(provider)
    return provider
