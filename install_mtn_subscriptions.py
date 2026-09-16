#!/usr/bin/env python3
from pathlib import Path
import re
import shutil
import subprocess
import sys

root = Path.cwd()
web = root / "predita_web.py"
ext = root / "mtn_subscriptions.py"
backup = root / "predita_web.py.pre_mtn_subscriptions.bak"

if not web.is_file():
    raise SystemExit("Run this from the predita-web repository directory; predita_web.py was not found.")
if not ext.is_file():
    raise SystemExit("mtn_subscriptions.py is missing. Copy it into the repository first.")

text = web.read_text(encoding="utf-8")
marker = "_register_mtn_subscriptions(app, _sys.modules[__name__])"

if marker in text:
    print("MTN Subscriptions integration is already registered.")
else:
    if not backup.exists():
        shutil.copy2(web, backup)
        print(f"Backup created: {backup.name}")

    pattern = re.compile(r'(?m)^if __name__ == [\"\']__main__[\"\']:\s*$')
    matches = list(pattern.finditer(text))
    if not matches:
        raise SystemExit("Could not find the __main__ entry point. No changes were made.")

    m = matches[-1]
    registration = '''# Optional MTN Subscriptions v2 extension.\n# Disabled unless PREDITA_ENABLE_MTN_SUBSCRIPTIONS=1 and server-side OAuth credentials exist.\nimport sys as _sys\nfrom mtn_subscriptions import register_mtn_subscriptions as _register_mtn_subscriptions\n_register_mtn_subscriptions(app, _sys.modules[__name__])\n\n'''
    new_text = text[:m.start()] + registration + text[m.start():]
    web.write_text(new_text, encoding="utf-8")
    print("Registered MTN Subscriptions v2 extension in predita_web.py")

print("Running syntax checks...")
subprocess.run([sys.executable, "-m", "py_compile", str(web), str(ext)], check=True)
print("Syntax checks passed.")

selftest = root / "predita_selftest.py"
if selftest.is_file():
    print("Running Predita self-test...")
    subprocess.run([sys.executable, str(selftest)], check=True)
    print("Predita self-test passed.")

print("\nIntegration installed but still DISABLED by default.")
print("Do not use the bearer token from MTN documentation.")
print("When MTN issues your own Production Key and Production Secret, configure them only as server environment variables.")
