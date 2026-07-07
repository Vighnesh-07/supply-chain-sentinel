"""
VulnApp — Intentionally Vulnerable Supply Chain Demo Application
================================================================

A FastAPI application that deliberately uses outdated and vulnerable
dependencies to demonstrate software supply chain security monitoring.

Endpoints exercise every declared dependency so that Syft can detect
them as actively-used components in the container image.

WARNING: Do NOT deploy this application in production environments.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
import requests as http_requests
import yaml
import json
import os
from datetime import datetime

# Import various dependencies to ensure they appear in the container
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import numpy as np
import pandas as pd
from jinja2 import Template
from lxml import etree
import jwt
from marshmallow import Schema, fields

app = FastAPI(
    title="VulnApp — Supply Chain Security Demo",
    description="Intentionally vulnerable application for supply chain monitoring research",
    version="1.0.0",
)

# ─── Encryption Setup ───────────────────────────────────────
FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)

JWT_SECRET = "demo-secret-key-not-for-production"


# ─── Marshmallow Schemas ────────────────────────────────────
class SensorSchema(Schema):
    sensor_id = fields.Int()
    temperature = fields.Float()
    humidity = fields.Float()
    pressure = fields.Float()


sensor_schema = SensorSchema(many=True)


# ═══════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════


# ─── Home & Health ───────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    """Landing page rendered with Jinja2 templates."""
    template = Template("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>VulnApp Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
                color: #e0e0e0;
                min-height: 100vh;
                padding: 40px;
            }
            .container { max-width: 800px; margin: 0 auto; }
            h1 {
                font-size: 2.2rem;
                background: linear-gradient(90deg, #00d4ff, #7b2ff7);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 8px;
            }
            .subtitle { color: #888; margin-bottom: 32px; }
            .endpoints {
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 12px;
                padding: 24px;
                backdrop-filter: blur(10px);
            }
            .endpoints h3 { color: #00d4ff; margin-bottom: 16px; }
            .endpoint {
                display: flex;
                align-items: center;
                padding: 10px 0;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }
            .endpoint:last-child { border-bottom: none; }
            .endpoint a {
                color: #7b2ff7;
                text-decoration: none;
                font-family: 'Consolas', monospace;
                font-weight: 600;
                min-width: 200px;
            }
            .endpoint a:hover { color: #00d4ff; }
            .endpoint span { color: #888; font-size: 0.9rem; }
            .warning {
                margin-top: 24px;
                padding: 12px 16px;
                background: rgba(255,107,107,0.1);
                border-left: 3px solid #ff6b6b;
                border-radius: 4px;
                color: #ff6b6b;
                font-size: 0.9rem;
            }
            .time { color: #555; font-size: 0.85rem; margin-top: 16px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 VulnApp</h1>
            <p class="subtitle">Supply Chain Security Demo Application</p>

            <div class="endpoints">
                <h3>Available Endpoints</h3>
                <div class="endpoint">
                    <a href="/health">/health</a>
                    <span>Application health check</span>
                </div>
                <div class="endpoint">
                    <a href="/info">/info</a>
                    <span>System and dependency information</span>
                </div>
                <div class="endpoint">
                    <a href="/crypto/encrypt?data=hello">/crypto/encrypt</a>
                    <span>Fernet symmetric encryption demo</span>
                </div>
                <div class="endpoint">
                    <a href="/data/generate">/data/generate</a>
                    <span>Generate random sensor data (NumPy + Pandas)</span>
                </div>
                <div class="endpoint">
                    <a href="/data/analyze">/data/analyze</a>
                    <span>Statistical analysis on sample data</span>
                </div>
                <div class="endpoint">
                    <a href="/xml/parse">/xml/parse</a>
                    <span>XML parsing demo (lxml)</span>
                </div>
                <div class="endpoint">
                    <a href="/auth/token?username=admin">/auth/token</a>
                    <span>Generate JWT authentication token</span>
                </div>
                <div class="endpoint">
                    <a href="/config">/config</a>
                    <span>YAML configuration parser</span>
                </div>
                <div class="endpoint">
                    <a href="/docs">/docs</a>
                    <span>Interactive API documentation (Swagger)</span>
                </div>
            </div>

            <div class="warning">
                ⚠️ This application intentionally uses outdated dependencies for security research purposes.
            </div>
            <p class="time">Server Time: {{ time }}</p>
        </div>
    </body>
    </html>
    """)
    return template.render(time=datetime.now().isoformat())


@app.get("/health")
async def health_check():
    """Application health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "uptime": "running",
    }


@app.get("/info")
async def system_info():
    """Return system and dependency version information."""
    return {
        "application": "VulnApp",
        "version": "1.0.0",
        "python_version": os.sys.version,
        "dependencies": {
            "fastapi": "0.68.0",
            "cryptography": "3.4.6",
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "PyJWT": jwt.__version__ if hasattr(jwt, "__version__") else "unknown",
            "PyYAML": yaml.__version__ if hasattr(yaml, "__version__") else "unknown",
        },
        "environment": os.environ.get("APP_ENV", "development"),
    }


# ─── Cryptography Endpoints ─────────────────────────────────

@app.get("/crypto/encrypt")
async def encrypt_data(data: str):
    """Encrypt plaintext using Fernet symmetric encryption."""
    encrypted = cipher.encrypt(data.encode())
    return {
        "original": data,
        "encrypted": encrypted.decode(),
        "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)",
        "key_length_bits": 256,
    }


@app.get("/crypto/decrypt")
async def decrypt_data(token: str):
    """Decrypt a Fernet-encrypted token."""
    try:
        decrypted = cipher.decrypt(token.encode())
        return {"decrypted": decrypted.decode(), "valid": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")


@app.get("/crypto/hash")
async def hash_data(data: str):
    """Generate a SHA-256 hash of the input data."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    hash_bytes = digest.finalize()
    return {
        "input": data,
        "sha256": hash_bytes.hex(),
        "algorithm": "SHA-256",
    }


# ─── Data Processing Endpoints ──────────────────────────────

@app.get("/data/generate")
async def generate_data():
    """Generate random sensor data using NumPy and format with Pandas."""
    np.random.seed(42)
    df = pd.DataFrame({
        "sensor_id": range(1, 11),
        "temperature": np.random.normal(72, 5, 10).round(2),
        "humidity": np.random.uniform(30, 80, 10).round(2),
        "pressure": np.random.normal(1013, 10, 10).round(2),
        "timestamp": [datetime.now().isoformat() for _ in range(10)],
    })
    validated = sensor_schema.dump(df.to_dict(orient="records"))
    return {
        "data": validated,
        "count": len(validated),
        "generated_at": datetime.now().isoformat(),
    }


@app.get("/data/analyze")
async def analyze_data():
    """Perform statistical analysis on sample sensor data."""
    np.random.seed(42)
    temps = np.random.normal(72, 5, 100)
    humidity = np.random.uniform(30, 80, 100)

    return {
        "temperature": {
            "mean": float(np.mean(temps)),
            "std": float(np.std(temps)),
            "min": float(np.min(temps)),
            "max": float(np.max(temps)),
            "percentiles": {
                "25th": float(np.percentile(temps, 25)),
                "50th": float(np.percentile(temps, 50)),
                "75th": float(np.percentile(temps, 75)),
            },
        },
        "humidity": {
            "mean": float(np.mean(humidity)),
            "std": float(np.std(humidity)),
            "min": float(np.min(humidity)),
            "max": float(np.max(humidity)),
        },
        "correlation": float(np.corrcoef(temps, humidity)[0, 1]),
        "sample_size": 100,
    }


# ─── XML Processing ─────────────────────────────────────────

@app.get("/xml/parse")
async def parse_xml():
    """Parse and extract data from XML using lxml."""
    sample_xml = """<?xml version="1.0"?>
    <infrastructure>
        <datacenter region="us-east-1">
            <server name="web-01" role="frontend" status="active" cpu="45"/>
            <server name="web-02" role="frontend" status="active" cpu="62"/>
            <server name="db-01" role="database" status="active" cpu="78"/>
            <server name="cache-01" role="cache" status="maintenance" cpu="12"/>
        </datacenter>
        <datacenter region="eu-west-1">
            <server name="web-03" role="frontend" status="active" cpu="33"/>
            <server name="db-02" role="database" status="standby" cpu="5"/>
        </datacenter>
    </infrastructure>"""

    root = etree.fromstring(sample_xml.encode())
    datacenters = []

    for dc in root.findall("datacenter"):
        servers = []
        for server in dc.findall("server"):
            servers.append({
                "name": server.get("name"),
                "role": server.get("role"),
                "status": server.get("status"),
                "cpu_usage": int(server.get("cpu", 0)),
            })
        datacenters.append({
            "region": dc.get("region"),
            "servers": servers,
            "server_count": len(servers),
        })

    return {
        "datacenters": datacenters,
        "total_servers": sum(dc["server_count"] for dc in datacenters),
        "parser": "lxml.etree",
    }


# ─── JWT Authentication Demo ────────────────────────────────

@app.get("/auth/token")
async def generate_token(username: str = "demo_user"):
    """Generate a JWT token for the given username."""
    payload = {
        "sub": username,
        "iat": datetime.now().timestamp(),
        "role": "viewer",
        "permissions": ["read"],
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return {"token": token, "type": "Bearer", "expires_in": "N/A (demo)"}


@app.get("/auth/verify")
async def verify_token(token: str):
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {"valid": True, "payload": payload}
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


# ─── External HTTP Demo ─────────────────────────────────────

@app.get("/fetch")
async def fetch_url(url: str = "https://httpbin.org/get"):
    """Fetch a URL using the requests library (demonstrates outbound traffic)."""
    try:
        response = http_requests.get(url, timeout=10)
        return {
            "url": url,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type"),
            "size_bytes": len(response.content),
            "response_time_ms": response.elapsed.total_seconds() * 1000,
        }
    except http_requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {str(e)}")


# ─── YAML Configuration Demo ────────────────────────────────

@app.get("/config")
async def get_config():
    """Parse a sample YAML configuration using PyYAML."""
    sample_config = """
    application:
      name: VulnApp
      version: 1.0.0
      debug: true
      features:
        - authentication
        - rate_limiting
        - logging
    database:
      host: localhost
      port: 5432
      name: vulnapp_db
      pool_size: 10
    security:
      cors_enabled: true
      rate_limit: 100
      jwt_expiry_seconds: 3600
    monitoring:
      enabled: true
      interval_seconds: 30
      exporters:
        - prometheus
        - datadog
    """
    config = yaml.safe_load(sample_config)
    return {"config": config, "parser": "PyYAML (yaml.safe_load)"}


# ═══════════════════════════════════════════════════════════════
# APPLICATION ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
