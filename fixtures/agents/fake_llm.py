"""A tiny OpenAI-compatible chat completions server for repeatable fixture runs.

Returns a fixed answer with token usage, or a tool call when the request offers
tools and no tool result is present yet, so agents exercise a model call, a tool
call and a second model call without any real provider or cost.

    python fake_llm.py 18080
"""

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        messages = body.get("messages", [])
        wants_tool = bool(body.get("tools")) and not any(m.get("role") == "tool" for m in messages)
        if wants_tool:
            tool = body["tools"][0]["function"]["name"]
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": tool, "arguments": json.dumps({"order_id": "A-1001"})}}],
            }
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": "The order A-1001 was refunded."}
            finish = "stop"
        out = {
            "id": f"chatcmpl-{int(time.time() * 1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model", "gpt-4o-mini"),
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 42 + 10 * len(messages), "completion_tokens": 12, "total_tokens": 54 + 10 * len(messages)},
        }
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 18080), Handler).serve_forever()
