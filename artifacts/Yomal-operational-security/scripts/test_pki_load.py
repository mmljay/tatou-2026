import os
from pathlib import Path
from rmap import RMAPServer

# Resolve key paths relative to this script, not the working directory.
BASE_DIR = Path(__file__).resolve().parent
RMAP_SERVER_PUB = BASE_DIR / "keys" / "server_pub.asc"
RMAP_SERVER_PRIV = BASE_DIR / "keys" / "group17_private.asc"
RMAP_CLIENTS_DIR = BASE_DIR / "keys" / "clients" / "pki"
PASSPHRASE = os.environ.get("RMAP_SERVER_KEY_PASSPHRASE", "")

print("[*] Initializing RMAP Connection Manager...")
print(f"[-] Loading Private Identity: {RMAP_SERVER_PRIV.name}")

try:
    rs = RMAPServer(
        RMAP_SERVER_PUB,
        RMAP_SERVER_PRIV,
        passphrase=PASSPHRASE or None,
        linkPrefix="",
        verbose=True
    )
    rs.loadIdentities(RMAP_CLIENTS_DIR)
    print("\n[+] SUCCESS: Cryptographic backend initialized perfectly.")
    
    if hasattr(rs, 'identities'):
        print(f"[+] Total target VM nodes discovered and trusted: {len(rs.identities)}")
        
except Exception as e:
    print(f"\n[!] Configuration or Decryption Failure: {e}")
    print("[!] Ensure the passphrase environment variable is set if the key is encrypted.")
    raise SystemExit(1) from e
