"""Drive each client through the stand-in with a clean environment.

Each case gets a fresh config dir and an environment built from scratch, so
nothing from the calling session (its login, its settings) reaches the client.
The stand-in's log for the case is moved to results/<case>.jsonl.
"""
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
H = open(os.path.join(HERE, "handle.txt")).read().strip()
CA = os.path.join(HERE, "mitm", "mitmproxy-ca-cert.pem")
PROXY = "http://127.0.0.1:18799"
CLAUDE = os.path.expanduser("~/.local/bin/claude")
OUT = os.path.join(HERE, "results")
os.makedirs(OUT, exist_ok=True)


def base_env(case: str) -> dict:
    cfg = os.path.join(HERE, "cfg", case)
    shutil.rmtree(cfg, ignore_errors=True)
    os.makedirs(cfg)
    return {
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": cfg,  # a throwaway home: no ~/.claude, no keychain-backed login lookup by path
        "USER": os.environ.get("USER", ""),
        "LANG": "en_US.UTF-8",
        "TERM": "dumb",
        "CLAUDE_CONFIG_DIR": os.path.join(cfg, ".claude"),
        "HTTPS_PROXY": PROXY, "HTTP_PROXY": PROXY,
        "https_proxy": PROXY, "http_proxy": PROXY,
        "NODE_EXTRA_CA_CERTS": CA, "SSL_CERT_FILE": CA, "REQUESTS_CA_BUNDLE": CA,
        "DISABLE_AUTOUPDATER": "1",
    }


def run(case: str, argv: list, extra: dict, stdin: str | None = None, timeout: int = 90):
    log = os.path.join(HERE, "log.jsonl")
    if os.path.exists(log):
        os.remove(log)
    env = base_env(case) | extra
    try:
        p = subprocess.run(argv, env=env, input=stdin, capture_output=True, text=True,
                           timeout=timeout, cwd=env["HOME"])
        code, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        code = "timeout"
        out = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = (e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
    rows = []
    if os.path.exists(log):
        rows = [json.loads(l) for l in open(log)]
        shutil.move(log, os.path.join(OUT, case + ".jsonl"))
    scrub = lambda s: s.replace(H, "<HANDLE>")[-1500:]
    with open(os.path.join(OUT, case + ".run.json"), "w") as f:
        json.dump({"case": case, "argv": [a.replace(H, "<HANDLE>") for a in argv],
                   "env_keys": sorted(extra), "exit": code,
                   "stdout_tail": scrub(out), "stderr_tail": scrub(err)}, f, indent=1)
    print(f"== {case}: exit {code}, {len(rows)} request(s)")
    for r in rows:
        print("  ", r["method"], r["host"] + r["path"], r["http_version"], json.dumps(r["credentials"]),
              "body-has-handle" if r["handle_in_body"] else "")


def mcp_config(case: str, servers: dict) -> str:
    path = os.path.join(HERE, "cfg", case + "-mcp.json")
    json.dump({"mcpServers": servers}, open(path, "w"))
    return path


def more():
    py = os.path.join(HERE, ".venv", "bin", "python")
    client = os.path.join(HERE, "py_mcp_client.py")
    remote = os.path.join(HERE, "node_modules", ".bin", "mcp-remote")
    init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "sp1", "version": "0"}}}) + "\n"
    return {
        # An unresolvable host: a request reaches the stand-in only through the proxy.
        "py-steer": lambda: run("py-steer", [py, client, "https://mcp.sp1.invalid/mcp",
                                             "Authorization", "Bearer " + H], {}, timeout=40),
        "py-linear": lambda: run("py-linear", [py, client, "https://mcp.linear.app/mcp",
                                               "Authorization", "Bearer " + H], {}, timeout=40),
        "py-sentry": lambda: run("py-sentry", [py, client, "https://mcp.sentry.dev/mcp",
                                               "Authorization", "Sentry-Bearer " + H], {}, timeout=40),
        "node-steer-plain": lambda: run("node-steer-plain", [remote, "https://mcp.sp1.invalid/mcp",
                                        "--header", "Authorization:Bearer " + H], {}, stdin=init, timeout=25),
        "node-steer-envproxy": lambda: run("node-steer-envproxy", [remote, "https://mcp.sp1.invalid/mcp",
                                           "--header", "Authorization:Bearer " + H],
                                           {"NODE_USE_ENV_PROXY": "1"}, stdin=init, timeout=25),
    }


if __name__ == "__main__":
    which = sys.argv[1:]
    prompt = ["-p", "Reply with the single word ok.", "--max-turns", "1"]
    cases = {
        "cc-api-key": lambda: run("cc-api-key", [CLAUDE, *prompt], {"ANTHROPIC_API_KEY": H}),
        "cc-auth-token": lambda: run("cc-auth-token", [CLAUDE, *prompt], {"ANTHROPIC_AUTH_TOKEN": H}),
        "cc-oauth-token": lambda: run("cc-oauth-token", [CLAUDE, *prompt], {"CLAUDE_CODE_OAUTH_TOKEN": H}),
    }

    def cc_mcp():
        case = "cc-mcp"
        cfg = mcp_config(case, {
            "linear": {"type": "http", "url": "https://mcp.linear.app/mcp",
                       "headers": {"Authorization": "Bearer " + H}},
            "sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp",
                       "headers": {"Authorization": "Sentry-Bearer " + H}},
            "cloudflare": {"type": "http", "url": "https://mcp.cloudflare.com/mcp",
                           "headers": {"Authorization": "Bearer " + H}},
        })
        run(case, [CLAUDE, *prompt, "--mcp-config", cfg, "--strict-mcp-config"],
            {"ANTHROPIC_API_KEY": "sk-ant-sp1-model-key-not-the-handle"})
    cases["cc-mcp"] = cc_mcp
    cases.update(more())
    for name in which or list(cases):
        cases[name]()
