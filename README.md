# 🛡️ Supply Chain Sentinel

> **Software Supply Chain Security Auditor & Active Runtime Threat Watchdog (HIDS)**
> A modular cybersecurity platform to secure Docker container applications across multiple languages.

---

## 🌟 Key Features

Sentinel implements a **hybrid security model** combining pre-runtime static analysis and active container runtime monitoring:

### 1. Multi-Ecosystem Dependency Auditing (SCA)
*   **Universal Version Checking:** Resolves dependencies and queries active versions across **8 ecosystems**: Python (PyPI), Node.js (npm), Go, Ruby (RubyGems), Java (Maven), Rust (crates.io), PHP (Packagist), and .NET (NuGet).
*   **Vulnerability Databases:** Queries Google OSV, GitHub Advisory, and npm audits to flag CVEs.
*   **Typosquatting Detection:** A custom edit-distance engine flags dependency typos attempting typosquatting hijacks against popular libraries.
*   **Local Threat Intelligence:** Evaluates packages against a curated database of known malicious libraries.

### 2. Behavioral Static Analysis & AST Scanning
*   **Tree-sitter AST Parsing:** Generates ASTs to inspect files in Python, JS/TS, Go, and Ruby.
*   **Suspicious Pattern Matching:** Flags dynamic execution (`eval()`, `atob()`), obfuscation, credential theft (accessing `AWS_ACCESS_KEY_ID`, `DATABASE_URL`), and sensitive file reads (like `/etc/passwd`).
*   **Entropy-Based Secret Detection:** Calculates Shannon Entropy to identify embedded API keys and high-entropy secrets.

### 3. Dynamic Network Attribution & Evasion Analysis
*   **Process Hooking & Attribution:** Monkey-patches Node.js core modules (`http`, `https`, `net`, `dns`) in memory. It matches raw TCP/UDP socket connections back to the specific initiating third-party package and file line.
*   **5-Layer Zero-Day Evasion Detection (HIDS):**
    *   **Layer 1 (Allowlisting):** Strict outbound domain and IP address matching.
    *   **Layer 2 (Domain Age):** Performs RDAP/WHOIS lookups to flag newly registered C2 domains (<30 days old).
    *   **Layer 3 (DNS Tunneling):** Flags high subdomain Shannon entropy and burst volume query anomalies.
    *   **Layer 4 (Raw IPs):** Identifies DNS bypasses where packages connect directly to hardcoded IP addresses.
    *   **Layer 5 (Process Escapes):** Intercepts subprocess creation (`child_process.spawn/exec`) to detect shell escape hacks (e.g. `curl`, `wget`, `bash` calls).

---

## 🚀 Quick Start

### Prerequisites
*   **Python 3.9+**
*   **Docker Desktop** (running)
*   **Syft** — [Install Guide](https://github.com/anchore/syft#installation)

### 1. Install Dependencies
```bash
cd monitor
pip install -r requirements.txt
```

### 2. Build the Demo Target Application
Build the vulnerable multi-dependency microservice demo:
```bash
docker build -t nexus-studio-app -f demo-apps/nexus-studio/Dockerfile demo-apps/nexus-studio
```

Run the container:
```bash
docker run -d --name nexus-studio-app -p 3000:3000 nexus-studio-app
```

### 3. Run the Security Audit
Scan the active container and enable network/evasion monitoring:
```bash
python monitor.py --container nexus-studio-app --net-monitor
```

### 4. View the Outputs
*   **Terminal Dashboard:** Standard color-coded security scorecard and threat reports printed via Rich.
*   **Detailed Excel Report:** Saved to `reports/nexus-studio-app/supply_chain_audit_YYYYMMDD_HHMMSS.xlsx`.
*   **Runtime Alerts Log:** Continuous evasion alerts logged to `monitor/runtime_alerts.log`.

---

## 📂 Project Structure

```
supply-chain-sentinel/
├── demo-apps/                  # Target test applications
│   └── nexus-studio/           #   Node.js microservice + malicious demo deps
│       ├── preload.cjs         #   Memory hooking instrumentation engine
│       └── Dockerfile          #   Container setup
├── demo-packages/              # Custom malicious test packages
├── monitor/                    # The core security scanner
│   ├── monitor.py              #   Orchestrator CLI
│   ├── requirements.txt        #   Python dependency requirements
│   └── utils/
│       ├── config.py           #   Allowlists and HIDS thresholds
│       ├── sbom.py             #   SBOM parser (multi-ecosystem)
│       ├── registry_client.py  #   Package registry lookup engine
│       ├── vuln_scanner.py     #   Google OSV API integration
│       ├── threat_intel.py     #   Typo-squatting & blocklist evaluator
│       ├── static_analysis.py  #   Shannon entropy secret scanner
│       ├── ast_scanner.py      #   Multi-language Tree-sitter AST scans
│       ├── runtime_scanner.py  #   Docker runtime container package extractor
│       └── runtime_network.py  #   Socket parser & 5-Layer Evasion Analyzer
├── reports/                    # Generated Excel reports
├── .gitignore
├── LICENSE                     # MIT License
└── README.md
```

---

## ⚠️ Disclaimer

This repository contains **intentionally malicious demo dependencies** and vulnerable endpoints for showcase purposes. Do not deploy these packages or scripts in a production system.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](file:///C:/Users/Vighnesh/.gemini/antigravity/scratch/supply-chain-sentinel/LICENSE) for details.
