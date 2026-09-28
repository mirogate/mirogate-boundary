"""Synthetic local-only demo: observe the exact JSON received by a mock provider.

Run from the installed checkout: python examples/capture_demo.py
No external provider is called. Rules-only by default, explicitly labelled.
"""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets
import threading

from mirogate_boundary.core import Engine
from mirogate_boundary.detectors import RuleDetector, OpenAIPrivacyDetector, HybridDetector
from mirogate_boundary.proxy import create_server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", help="Optional pinned local model, for actual hybrid inference")
    args = parser.parse_args()
    detector = RuleDetector()
    mode = "rules-only (no AI model)"
    if args.checkpoint:
        detector = HybridDetector(detector, OpenAIPrivacyDetector(args.checkpoint))
        mode = "hybrid (actual local model inference)"
    captured = []
    class MockProvider(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            captured.append(body)
            raw = json.dumps({"choices":[{"finish_reason":"stop", "message":{
                "role":"assistant", "content":body["messages"][0]["content"]}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    upstream = HTTPServer(("127.0.0.1",0),MockProvider)
    token = secrets.token_urlsafe(32)
    boundary = create_server(lambda: Engine(detector),
        f"http://127.0.0.1:{upstream.server_port}/v1/chat/completions",
        None, token, port=0, restore=True)
    threads = [threading.Thread(target=s.serve_forever,daemon=True) for s in (upstream,boundary)]
    for thread in threads: thread.start()
    try:
        original = "Email: demo@example.com; Phone: +44 7700 900123"
        client = http.client.HTTPConnection("127.0.0.1",boundary.server_port,timeout=300)
        client.request("POST","/v1/chat/completions",
            json.dumps({"model":"demo-model", "messages":[{"role":"user","content":original}]}),
            {"Content-Type":"application/json","Authorization":"Bearer "+token})
        response = client.getresponse()
        output = json.loads(response.read())
        client.close()
        if response.status != 200 or len(captured) != 1:
            raise RuntimeError("Local demonstration failed; no success claim")
        provider_text = captured[0]["messages"][0]["content"]
        assert "demo@example.com" not in provider_text
        assert "+44 7700 900123" not in provider_text
        assert output["choices"][0]["message"]["content"] == original
        print(json.dumps({"mode":mode,"external_calls":0,"synthetic_original":original,
                          "mock_provider_received":provider_text,
                          "local_roundtrip_exact":True},indent=2))
    finally:
        for server in (boundary,upstream):
            server.shutdown()
            server.server_close()
        for thread in threads: thread.join()


if __name__ == "__main__": main()
