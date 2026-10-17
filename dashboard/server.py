"""
Supply Chain Sentinel — Centralized Security Dashboard Server
==============================================================
FastAPI-powered backend providing REST APIs, live telemetry,
on-demand auditing, and interactive web dashboard visualization.

Usage:
    python dashboard/server.py [--port 8080] [--host 0.0.0.0]
"""

import os
import sys
import json
import glob
import time
import subprocess
import threading
from datetime import datetime
from typing import List, Dict, Optional, Any

from fastapi import FastAPI, UploadFile, File, BackgroundTasks, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Ensure monitor package is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONITOR_DIR = os.path.join(PROJECT_ROOT, "monitor")
sys.path.insert(0, MONITOR_DIR)

app = FastAPI(
    title="Supply Chain Sentinel — Security Operations Center",
    description="Centralized Web Dashboard & Real-Time Threat Intelligence Console",
    version="2.0.0",
)

# Enable CORS for local testing and iframe embedding
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORT_DIR = os.path.join(MONITOR_DIR, "reports")
LATEST_AUDIT_FILE = os.path.join(REPORT_DIR, "latest_audit.json")
RUNTIME_LOG_FILE = os.path.join(REPORT_DIR, "runtime_alerts.log")
EBPF_LOG_FILE = os.path.join(REPORT_DIR, "runtime_alerts_ebpf.log")

# In-memory background scan job state
active_jobs: Dict[str, Dict[str, Any]] = {}


# ═══════════════════════════════════════════════════════════════
# HELPER DATA LOADERS
# ═══════════════════════════════════════════════════════════════

def _generate_default_audit_data() -> Dict[str, Any]:
    """Fallback sample dataset based on nexus-studio-app for first launch."""
    sample_packages = [
        {
            "package": "wallet-drainer",
            "ecosystem": "npm",
            "current_version": "1.0.0",
            "latest_version": "1.0.0",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cve_ids": ["MAL-2026-NEXUS01"],
            "vuln_count": 1,
            "is_malicious": True,
            "threat_status": "Malicious",
            "threat_score": 100,
            "threat_sources": ["Local Blocklist: Known wallet drainer implant", "Typo-squatting detection"],
            "ioc_ast": ["eval() call detected inside obfuscated hex array at server.js:14"],
            "ioc_entropy_secrets": ["api_key='sk_live_948194a8b7c6d5e4f3a2b1' (Shannon entropy: 4.82)"],
            "ioc_wallets": ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh (Bitcoin Native SegWit)"],
            "ioc_urls": ["http://185.220.101.5:4444/exfil"],
            "ioc_ips": ["185.220.101.5"],
            "risk_summary": "1 Crypto wallet, 1 High-entropy secret, 1 Malicious AST implant",
            "ai_verdict": "MALICIOUS",
            "ai_summary": "High-confidence zero-day cryptocurrency theft payload disguised as utility dependency.",
        },
        {
            "package": "b64-encoder",
            "ecosystem": "npm",
            "current_version": "1.0.0",
            "latest_version": "1.0.0",
            "severity": "CRITICAL",
            "cvss_score": 9.2,
            "cve_ids": ["MAL-2026-NEXUS02"],
            "vuln_count": 1,
            "is_malicious": True,
            "threat_status": "Malicious",
            "threat_score": 100,
            "threat_sources": ["OSV Malware Database (MAL-2026-NEXUS02)"],
            "ioc_ast": ["child_process.exec() decoding base64 payload at index.js:28"],
            "ioc_entropy_secrets": [],
            "ioc_wallets": [],
            "ioc_urls": ["https://webhook.site/7b94101e-c2-backdoor"],
            "ioc_ips": [],
            "risk_summary": "Base64 payload dropper and reverse shell execution hook",
            "ai_verdict": "MALICIOUS",
            "ai_summary": "Executes decoded shell script from base64 string during package initialization.",
        },
        {
            "package": "lodash",
            "ecosystem": "npm",
            "current_version": "4.17.20",
            "latest_version": "4.17.21",
            "severity": "HIGH",
            "cvss_score": 7.4,
            "cve_ids": ["CVE-2020-8203", "CVE-2020-28500"],
            "vuln_count": 2,
            "is_malicious": False,
            "threat_status": "Vulnerable",
            "threat_score": 55,
            "threat_sources": ["GitHub Advisory Database (GHSA-p6mc-m468-83gw)"],
            "ioc_ast": [],
            "ioc_entropy_secrets": [],
            "ioc_wallets": [],
            "ioc_urls": [],
            "ioc_ips": [],
            "risk_summary": "Prototype Pollution and Regular Expression Denial of Service",
            "ai_verdict": "BENIGN",
            "ai_summary": "Standard open-source library with known CVEs; upgrade to 4.17.21 recommended.",
        },
        {
            "package": "express",
            "ecosystem": "npm",
            "current_version": "4.18.2",
            "latest_version": "4.19.2",
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "cve_ids": ["CVE-2024-29041"],
            "vuln_count": 1,
            "is_malicious": False,
            "threat_status": "Outdated",
            "threat_score": 30,
            "threat_sources": [],
            "ioc_ast": [],
            "ioc_entropy_secrets": [],
            "ioc_wallets": [],
            "ioc_urls": [],
            "ioc_ips": [],
            "risk_summary": "Open redirect in encodeUrl",
            "ai_verdict": "BENIGN",
            "ai_summary": "Web framework library with minor update available.",
        },
        {
            "package": "requests",
            "ecosystem": "PyPI",
            "current_version": "2.31.0",
            "latest_version": "2.32.3",
            "severity": "LOW",
            "cvss_score": 3.7,
            "cve_ids": ["CVE-2024-35195"],
            "vuln_count": 1,
            "is_malicious": False,
            "threat_status": "Clean",
            "threat_score": 15,
            "threat_sources": [],
            "ioc_ast": [],
            "ioc_entropy_secrets": [],
            "ioc_wallets": [],
            "ioc_urls": [],
            "ioc_ips": [],
            "risk_summary": "",
            "ai_verdict": "BENIGN",
            "ai_summary": "Popular HTTP client library with standard minor patch available.",
        },
        {
            "package": "urllib3",
            "ecosystem": "PyPI",
            "current_version": "2.2.2",
            "latest_version": "2.2.2",
            "severity": "NONE",
            "cvss_score": 0.0,
            "cve_ids": [],
            "vuln_count": 0,
            "is_malicious": False,
            "threat_status": "Clean",
            "threat_score": 1,
            "threat_sources": [],
            "ioc_ast": [],
            "ioc_entropy_secrets": [],
            "ioc_wallets": [],
            "ioc_urls": [],
            "ioc_ips": [],
            "risk_summary": "",
            "ai_verdict": "BENIGN",
            "ai_summary": "Fully verified and compliant package.",
        },
    ]

    return {
        "target": "nexus-studio-app:latest",
        "timestamp": datetime.now().isoformat(),
        "packages_scanned": len(sample_packages),
        "audit_data": sample_packages,
    }


def load_latest_audit() -> Dict[str, Any]:
    """Load latest audit report data from JSON cache, SARIF files, or default sample."""
    # 1. Try reading latest_audit.json
    if os.path.exists(LATEST_AUDIT_FILE):
        try:
            with open(LATEST_AUDIT_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass

    # 2. Try parsing latest .sarif file in reports directory
    sarif_files = glob.glob(os.path.join(REPORT_DIR, "*.sarif"))
    if sarif_files:
        latest_sarif = max(sarif_files, key=os.path.getctime)
        try:
            with open(latest_sarif, "r", encoding="utf-8") as fh:
                sarif_doc = json.load(fh)
            
            runs = sarif_doc.get("runs", [])
            results = runs[0].get("results", []) if runs else []
            packages = []

            for r in results:
                props = r.get("properties", {})
                pkg_name = props.get("package", r.get("ruleId", "unknown"))
                ecosystem = props.get("ecosystem", "npm")
                version = props.get("version", "1.0.0")
                level = r.get("level", "warning")
                
                sev = "HIGH" if level == "error" else ("MEDIUM" if level == "warning" else "LOW")
                is_mal = "MAL" in r.get("ruleId", "") or "SSC002" in r.get("ruleId", "") or "SSC003" in r.get("ruleId", "")

                packages.append({
                    "package": pkg_name,
                    "ecosystem": ecosystem,
                    "current_version": version,
                    "latest_version": version,
                    "severity": sev,
                    "cvss_score": 8.5 if sev == "HIGH" else 4.5,
                    "cve_ids": [r.get("ruleId", "")],
                    "vuln_count": 1,
                    "is_malicious": is_mal,
                    "threat_status": "Malicious" if is_mal else "Vulnerable",
                    "threat_score": 90 if is_mal else 50,
                    "threat_sources": [r.get("message", {}).get("text", "")],
                    "ioc_ast": [],
                    "ioc_entropy_secrets": [],
                    "ioc_wallets": [],
                    "ioc_urls": [],
                    "ioc_ips": [],
                    "risk_summary": r.get("message", {}).get("text", "")[:120],
                    "ai_verdict": "MALICIOUS" if is_mal else "SUSPICIOUS",
                    "ai_summary": r.get("message", {}).get("text", ""),
                })

            if packages:
                return {
                    "target": "imported-sarif:latest",
                    "timestamp": datetime.fromtimestamp(os.path.getctime(latest_sarif)).isoformat(),
                    "packages_scanned": len(packages),
                    "audit_data": packages,
                }
        except Exception:
            pass

    # 3. Fallback to rich default dataset
    return _generate_default_audit_data()


# ═══════════════════════════════════════════════════════════════
# REST API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.get("/api/overview")
def get_overview() -> Dict[str, Any]:
    """Retrieve high-level executive security metrics and system status."""
    audit = load_latest_audit()
    packages = audit.get("audit_data", [])

    total = len(packages)
    crit = sum(1 for p in packages if p.get("severity") == "CRITICAL")
    high = sum(1 for p in packages if p.get("severity") == "HIGH")
    med = sum(1 for p in packages if p.get("severity") == "MEDIUM")
    low = sum(1 for p in packages if p.get("severity") == "LOW")
    clean = sum(1 for p in packages if p.get("severity") in ("NONE", "Clean") and not p.get("is_malicious"))

    malicious = sum(1 for p in packages if p.get("is_malicious"))
    secrets = sum(len(p.get("ioc_entropy_secrets", [])) for p in packages)
    wallets = sum(len(p.get("ioc_wallets", [])) for p in packages)
    ast_findings = sum(len(p.get("ioc_ast", [])) for p in packages)

    # Calculate compliance health score (0 - 100)
    # Deductions: Malicious = -25, Critical = -15, High = -8, Medium = -3
    deductions = (malicious * 25) + (crit * 15) + (high * 8) + (med * 3)
    health_score = max(5, min(100, 100 - deductions)) if total > 0 else 100

    # Ecosystem distribution
    eco_dist: Dict[str, int] = {}
    for p in packages:
        eco = p.get("ecosystem", "Other")
        eco_dist[eco] = eco_dist.get(eco, 0) + 1

    # eBPF / Kernel status
    from utils.ebpf_monitor import get_ebpf_capabilities
    caps = get_ebpf_capabilities()

    return {
        "health_score": health_score,
        "target": audit.get("target", "nexus-studio-app:latest"),
        "timestamp": audit.get("timestamp", datetime.now().isoformat()),
        "total_packages": total,
        "critical_count": crit,
        "high_count": high,
        "medium_count": med,
        "low_count": low,
        "clean_count": clean,
        "malicious_count": malicious,
        "secrets_count": secrets,
        "wallets_count": wallets,
        "ast_findings_count": ast_findings,
        "ecosystem_distribution": eco_dist,
        "ebpf_capabilities": caps,
    }


@app.get("/api/packages")
def get_packages(
    search: Optional[str] = Query(None, description="Search by name, CVE, or threat source"),
    ecosystem: Optional[str] = Query(None, description="Filter by ecosystem (npm, PyPI, Go, etc.)"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, etc.)"),
    threats_only: bool = Query(False, description="Filter to show only malicious or vulnerable packages"),
) -> List[Dict[str, Any]]:
    """Retrieve detailed dependency inventory with granular filtering."""
    audit = load_latest_audit()
    packages = audit.get("audit_data", [])

    filtered = []
    for p in packages:
        # Search query matching
        if search:
            query = search.lower()
            name_match = query in p.get("package", "").lower()
            cve_match = any(query in str(c).lower() for c in p.get("cve_ids", []))
            threat_match = any(query in str(t).lower() for t in p.get("threat_sources", []))
            if not (name_match or cve_match or threat_match):
                continue

        # Ecosystem filter
        if ecosystem and ecosystem.lower() != "all":
            if p.get("ecosystem", "").lower() != ecosystem.lower():
                continue

        # Severity filter
        if severity and severity.upper() != "ALL":
            if p.get("severity", "").upper() != severity.upper():
                continue

        # Threats-only toggle
        if threats_only:
            is_threat = (
                p.get("is_malicious")
                or p.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
                or len(p.get("ioc_ast", [])) > 0
                or len(p.get("ioc_entropy_secrets", [])) > 0
            )
            if not is_threat:
                continue

        filtered.append(p)

    return filtered


@app.get("/api/containers")
def get_containers() -> List[Dict[str, Any]]:
    """Query live Docker daemon for running containers and detected ecosystems."""
    try:
        from utils.runtime_scanner import get_all_running_containers, probe_container_runtimes
        container_names = get_all_running_containers()
        containers = []
        for name in container_names:
            runtimes = probe_container_runtimes(name, include_os=True)
            containers.append({
                "name": name,
                "status": "running",
                "runtimes": runtimes,
                "is_monitored": True,
            })
        return containers
    except Exception as e:
        return [
            {"name": "nexus-studio-app", "status": "running", "runtimes": ["Node.js", "npm"], "is_monitored": True},
            {"name": "sentinel-agent", "status": "standby", "runtimes": ["Linux eBPF"], "is_monitored": False},
        ]


@app.get("/api/runtime/telemetry")
def get_runtime_telemetry() -> Dict[str, Any]:
    """Fetch live container socket telemetry and recent HIDS / eBPF alert events."""
    alerts = []
    # Read last 50 lines from runtime alerts log
    if os.path.exists(RUNTIME_LOG_FILE):
        try:
            with open(RUNTIME_LOG_FILE, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
                alerts = [l.strip() for l in lines[-50:] if l.strip()]
        except Exception:
            pass

    # Read last 50 lines from eBPF alerts log
    ebpf_alerts = []
    if os.path.exists(EBPF_LOG_FILE):
        try:
            with open(EBPF_LOG_FILE, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
                ebpf_alerts = [l.strip() for l in lines[-50:] if l.strip()]
        except Exception:
            pass

    # Active sockets
    sockets = []
    try:
        from utils.runtime_network import get_container_sockets
        sockets = get_container_sockets("nexus-studio-app")
    except Exception:
        # Sample mock sockets for visual demo
        sockets = [
            {"protocol": "TCP", "local_ip": "172.18.0.3", "local_port": 3000, "remote_ip": "0.0.0.0", "remote_port": 0, "state": "LISTEN", "risk": "PRIVATE"},
            {"protocol": "TCP", "local_ip": "172.18.0.3", "local_port": 52144, "remote_ip": "185.220.101.5", "remote_port": 4444, "state": "ESTABLISHED", "risk": "SUSPICIOUS_PORT", "attributed_package": "wallet-drainer"},
        ]

    return {
        "sockets": sockets,
        "alerts": alerts + ebpf_alerts,
        "total_alerts": len(alerts) + len(ebpf_alerts),
    }


@app.get("/api/reports")
def list_reports() -> List[Dict[str, Any]]:
    """List historical audit reports available for download."""
    reports = []
    os.makedirs(REPORT_DIR, exist_ok=True)
    for f in os.listdir(REPORT_DIR):
        f_path = os.path.join(REPORT_DIR, f)
        if os.path.isfile(f_path):
            ext = os.path.splitext(f)[1].lower()
            if ext in (".xlsx", ".sarif", ".json", ".log"):
                size_kb = round(os.path.getsize(f_path) / 1024, 1)
                mtime = datetime.fromtimestamp(os.path.getmtime(f_path)).strftime("%Y-%m-%d %H:%M:%S")
                reports.append({
                    "filename": f,
                    "type": ext.lstrip(".").upper(),
                    "size_kb": size_kb,
                    "date": mtime,
                })
    return sorted(reports, key=lambda x: x["date"], reverse=True)


@app.get("/api/reports/{filename}/download")
def download_report(filename: str):
    """Serve report file for download."""
    safe_path = os.path.join(REPORT_DIR, os.path.basename(filename))
    if os.path.exists(safe_path):
        return FileResponse(safe_path, filename=filename)
    return JSONResponse(status_code=404, content={"error": "Report not found"})


# ═══════════════════════════════════════════════════════════════
# SCAN TRIGGER & BACKGROUND ORCHESTRATION
# ═══════════════════════════════════════════════════════════════

def _run_background_scan(job_id: str, target: str, include_os: bool):
    """Execute scan in a background thread and capture status logs."""
    active_jobs[job_id]["status"] = "running"
    active_jobs[job_id]["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Initializing scan for '{target}'...")

    try:
        cmd = [
            sys.executable,
            os.path.join(MONITOR_DIR, "monitor.py"),
            "--image", target,
            "--report-dir", REPORT_DIR,
        ]
        if include_os:
            cmd.append("--include-os")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=MONITOR_DIR,
        )

        for line in iter(proc.stdout.readline, ""):
            clean_line = line.strip()
            if clean_line:
                active_jobs[job_id]["logs"].append(clean_line)

        proc.stdout.close()
        return_code = proc.wait()

        if return_code == 0:
            active_jobs[job_id]["status"] = "completed"
            active_jobs[job_id]["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Audit completed successfully.")
        else:
            active_jobs[job_id]["status"] = "completed_with_warnings"
            active_jobs[job_id]["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Audit finished with gate status code {return_code}.")
    except Exception as e:
        active_jobs[job_id]["status"] = "failed"
        active_jobs[job_id]["logs"].append(f"[ERROR] Scan execution failed: {str(e)}")


@app.post("/api/scan")
def trigger_scan(
    background_tasks: BackgroundTasks,
    target: str = Query("nexus-studio-app:latest", description="Docker image or container name to scan"),
    include_os: bool = Query(False, description="Whether to include OS packages in audit"),
) -> Dict[str, Any]:
    """Trigger an on-demand security audit in the background."""
    job_id = f"job_{int(time.time())}"
    active_jobs[job_id] = {
        "job_id": job_id,
        "target": target,
        "status": "queued",
        "started_at": datetime.now().isoformat(),
        "logs": [],
    }
    background_tasks.add_task(_run_background_scan, job_id, target, include_os)
    return {"job_id": job_id, "status": "queued", "target": target}


@app.get("/api/scan/{job_id}/status")
def get_scan_status(job_id: str) -> Dict[str, Any]:
    """Get status and logs for a running or completed audit job."""
    if job_id in active_jobs:
        return active_jobs[job_id]
    return JSONResponse(status_code=404, content={"error": "Job ID not found"})


@app.post("/api/upload-sbom")
async def upload_sbom(file: UploadFile = File(...)):
    """Upload a custom CycloneDX JSON or SARIF file to visualize immediately."""
    try:
        content = await file.read()
        parsed = json.loads(content.decode("utf-8"))

        # Check if it's SARIF format
        if "runs" in parsed:
            save_path = os.path.join(REPORT_DIR, f"uploaded_{file.filename}")
            with open(save_path, "wb") as fh:
                fh.write(content)
            return {"status": "success", "format": "SARIF 2.1.0", "message": "SARIF report ingested successfully."}

        # Check if it's CycloneDX format
        if "components" in parsed:
            save_path = os.path.join(REPORT_DIR, f"uploaded_{file.filename}")
            with open(save_path, "wb") as fh:
                fh.write(content)
            return {"status": "success", "format": "CycloneDX JSON", "components_found": len(parsed.get("components", []))}

        return JSONResponse(status_code=400, content={"error": "Unsupported file format. Please upload CycloneDX JSON or SARIF 2.1.0."})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to parse uploaded file: {str(e)}"})


# ═══════════════════════════════════════════════════════════════
# STATIC FRONTEND SERVING
# ═══════════════════════════════════════════════════════════════

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    """Serve the primary single-page cybersecurity web dashboard."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as fh:
            return HTMLResponse(content=fh.read())
    return HTMLResponse("<h1>Supply Chain Sentinel Dashboard</h1><p>Static index.html not initialized.</p>")


# ═══════════════════════════════════════════════════════════════
# STANDALONE SERVER ENTRYPOINT
# ═══════════════════════════════════════════════════════════════

def start_dashboard(host: str = "0.0.0.0", port: int = 8080):
    """Launch the dashboard web server with Uvicorn."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()
    console.print(Panel(
        f"[bold bright_cyan]SUPPLY CHAIN SENTINEL -- SECURITY OPERATIONS CENTER[/]\n\n"
        f"  [bold green][>>] Web Dashboard URL:[/] [bold underline bright_white]http://localhost:{port}[/]\n"
        f"  [dim]REST API Documentation :[/] [underline]http://localhost:{port}/docs[/]\n"
        f"  [dim]Listening Interface    :[/] {host}:{port}\n"
        f"  [dim]Reports Root Directory :[/] {REPORT_DIR}",
        title="[bold cyan]SOC Dashboard Active[/]",
        border_style="cyan",
        padding=(1, 2),
    ))
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Supply Chain Sentinel Dashboard Server")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    args = parser.parse_args()
    start_dashboard(host=args.host, port=args.port)
