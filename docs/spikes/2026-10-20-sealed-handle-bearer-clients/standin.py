"""mitmproxy addon: a TLS-terminating stand-in that never forwards.

Every request is answered locally. For each request it appends one JSON line
to log.jsonl with the host, method, path, header names, and for each
credential-shaped header whether its value is exactly the handle, `Bearer `
plus the handle, or something else (then only its length and a short hash,
never the value).
"""
import hashlib
import json
import os

from mitmproxy import http

HERE = os.path.dirname(os.path.abspath(__file__))
HANDLE = open(os.path.join(HERE, "handle.txt")).read().strip()
LOG = os.path.join(HERE, "log.jsonl")
TARGETS = {"api.anthropic.com", "mcp.linear.app", "mcp.sentry.dev", "mcp.cloudflare.com"}
CRED_WORDS = ("authorization", "api-key", "apikey", "token", "secret", "cookie")


def classify(value: str) -> dict:
    if value == HANDLE:
        return {"match": "handle"}
    if value == "Bearer " + HANDLE:
        return {"match": "Bearer handle"}
    if HANDLE in value:
        return {"match": "contains handle", "len": len(value),
                "around": value.replace(HANDLE, "<HANDLE>")[:80]}
    return {"match": "other", "len": len(value),
            "sha256_8": hashlib.sha256(value.encode()).hexdigest()[:8]}


def request(flow: http.HTTPFlow) -> None:
    req = flow.request
    creds = {}
    for name, value in req.headers.items(multi=True):
        if any(w in name.lower() for w in CRED_WORDS):
            creds[name] = classify(value)
    body_has_handle = HANDLE.encode() in (req.raw_content or b"")
    row = {
        "client": os.environ.get("SP1_CLIENT", ""),
        "host": req.pretty_host,
        "method": req.method,
        "path": req.path.split("?")[0],
        "http_version": req.http_version,
        "header_names": [n for n, _ in req.headers.items(multi=True)],
        "credentials": creds,
        "handle_in_body": body_has_handle,
    }
    with open(LOG, "a") as f:
        f.write(json.dumps(row) + "\n")
    if req.pretty_host.startswith("mcp."):
        # A minimal MCP server, so a client never falls back to an OAuth
        # sign-in (which would open a browser).
        if req.method != "POST":
            flow.response = http.Response.make(405, b"", {})
            return
        try:
            msg = json.loads(req.raw_content or b"{}")
        except ValueError:
            msg = {}
        if "id" not in msg:
            flow.response = http.Response.make(202, b"", {})
            return
        if msg.get("method") == "initialize":
            result = {"protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "sp1-stand-in", "version": "0"}}
        else:
            result = {"tools": []}
        flow.response = http.Response.make(
            200, json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}),
            {"content-type": "application/json"})
        return
    if req.pretty_host in TARGETS:
        flow.response = http.Response.make(
            401,
            json.dumps({"type": "error", "error": {"type": "authentication_error",
                                                   "message": "sp1 stand-in"}}),
            {"content-type": "application/json"},
        )
    else:
        flow.response = http.Response.make(403, b"sp1 stand-in: not forwarded",
                                           {"content-type": "text/plain"})
