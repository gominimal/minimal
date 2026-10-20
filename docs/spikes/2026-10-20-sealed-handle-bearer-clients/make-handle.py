"""Write handle.txt: an opaque value shaped like a compact signed handle.

Three base64url segments joined by dots, 484 characters, with a random
signature. Nothing verifies it; the spike only asks whether clients send it
unchanged.
"""
import base64
import json
import os

b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
head = b(json.dumps({"alg": "EdDSA", "kid": "client-local", "typ": "min-store-handle"}).encode())
body = b(json.dumps({
    "store": "keychain", "id": "claude", "up": ["api.anthropic.com"],
    "form": {"header": "Authorization", "prefix": "Bearer "}, "exp": 1893456000,
    "box": "0199f0c2-7a3e-7cc1-9d1e-" + os.urandom(6).hex(), "n": os.urandom(16).hex(),
}).encode())
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "handle.txt"), "w") as f:
    f.write(head + "." + body + "." + b(os.urandom(64)))
