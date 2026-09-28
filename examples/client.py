"""Explicit live-provider client example. Unlike capture_demo.py this can incur charges.

Start Boundary separately; set BOUNDARY_LOCAL_TOKEN and BOUNDARY_MODEL locally.
No provider credential belongs in this client. Uses synthetic example input only.
"""
import http.client
import json
import os


def main():
    token = os.environ.get("BOUNDARY_LOCAL_TOKEN")
    model = os.environ.get("BOUNDARY_MODEL")
    if not token or not model:
        raise SystemExit("Set BOUNDARY_LOCAL_TOKEN and BOUNDARY_MODEL first; see docs/proxy.md")
    body = {"model": model, "stream": False, "messages": [
        {"role":"user", "content":"Summarize this synthetic contact: Email: demo@example.com"}
    ]}
    client = http.client.HTTPConnection("127.0.0.1",8787,timeout=300)
    try:
        client.request("POST","/v1/chat/completions",json.dumps(body).encode(),
                       {"Content-Type":"application/json", "Authorization":"Bearer "+token})
        response = client.getresponse()
        raw = response.read(2_097_153)
        if len(raw) > 2_097_152:
            raise SystemExit("Response exceeded example client limit")
        # May contain sensitive model output in real applications; do not log it by default.
        print(json.dumps({"status":response.status, "response":json.loads(raw)},indent=2))
    finally:
        client.close()


if __name__ == "__main__": main()
