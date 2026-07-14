# Supply Chain Malware Evasion: Research & Defensive Architecture

## Introduction

Modern supply chain malware no longer simply drops a payload and hopes for the best. To maximize impact and dwell time, attackers have developed sophisticated "evasion layers" designed to beat detection capabilities, ensuring the malware actually executes its objective without triggering alerts or stopping prematurely due to security scrutiny.

During this internship, we researched and engineered a multi-layered detection architecture (Supply Chain Sentinel) specifically designed to counteract these evasion techniques. This document outlines the adversarial evasion methods we researched and how our 5-Layer HIDS (Host-based Intrusion Detection System) neutralizes them.

---

## 1. Environment Keying & Sandbox Evasion

### The Adversary's Goal
Malware attempts to determine if it is running in a security researcher's sandbox, an automated analysis pipeline, or the actual intended victim's environment. If the environment looks "suspicious" (e.g., standard CI/CD hostnames, specific MAC addresses, lack of user files), the malware will exit cleanly to avoid detection.

### Examples of Evasion
*   **Time Delays (Sleeps):** Pausing execution to outlast sandbox timeouts.
*   **Host Checking:** Querying `hostname`, `whoami`, or specific environment variables.
*   **Domain Allowlisting:** Reaching out to external services to verify the target's public IP address before downloading the second-stage payload.

### Our Detection Capability
Instead of relying on static signatures, our dynamic monitor observes the package's behavior. We use a customized runtime tracing module that intercepts and logs the package's attempts to read environment variables or execute specific shell commands. If a package aggressively probes the environment without a legitimate reason, our **Layer 5 (Process Escape Detection)** flags the behavior.

---

## 2. Network Anonymity & C2 Concealment

### The Adversary's Goal
Once the malware decides to execute, it must establish a Command and Control (C2) channel or exfiltrate stolen data (like AWS credentials) without triggering network firewalls.

### Examples of Evasion
*   **Fast-Flux DNS:** Rapidly changing the IP address associated with a domain name to evade IP blocklists.
*   **Domain Generation Algorithms (DGAs):** Generating thousands of random-looking domains, only one of which is actually registered by the attacker.
*   **Legitimate Services as C2:** Using Telegram, Discord, GitHub Issues, or Pastebin for C2 communication, blending malicious traffic with normal web traffic.

### Our Detection Capability
We implemented a robust, multi-tiered network monitoring system:
*   **Layer 1 (Allowlist Enforcer):** Checks all outbound connections against a strict baseline of known-good ecosystem registries.
*   **Layer 2 (Suspicious Domain Scanner):** Analyzes domain age and reputation. Newly registered domains or domains with poor reputations are immediately flagged.
*   **Layer 3 (DNS Anomaly Detector):** Identifies fast-flux behavior, excessively short TTLs, or patterns indicative of DGAs.
*   **Layer 4 (Raw IP Detection):** Detects connections that bypass DNS entirely and connect directly to hardcoded IP addresses, a strong indicator of malicious intent.

---

## 3. Process Escapes & Behavioral Obfuscation

### The Adversary's Goal
Attackers know that network connections or file drops might be monitored. To circumvent this, they attempt to "escape" the initial process and inject code into legitimate, trusted processes, or spawn hidden background processes.

### Examples of Evasion
*   **Shell Spawning:** Using `child_process.exec()` or `os.system()` to spawn a shell and execute raw commands (e.g., `curl | bash`).
*   **Living off the Land (LotL):** Using built-in system tools (like `certutil` on Windows or `wget` on Linux) to perform malicious actions, making the activity look like normal administration.
*   **In-Memory Execution:** Downloading and executing payloads directly in memory without ever writing a file to disk, bypassing traditional anti-virus scanners.

### Our Detection Capability
This was the final, critical stage of our internship development. We implemented **Layer 5 (Process Escape Detection)**:
*   We created `preload.cjs` (for Node.js) and equivalent wrappers for other ecosystems to actively hook and intercept process spawning APIs.
*   By monitoring `child_process`, `exec`, and `spawn`, we can detect exactly *which* package is attempting to break out of the runtime environment.
*   We categorize these escapes by severity. For example, spawning a generic `python` script might be low severity, but executing `sh -c curl ... | bash` is flagged as CRITICAL.

---

## Summary of the 5-Layer Evasion Detection Architecture

By integrating these detection layers, Supply Chain Sentinel shifts from being a simple static vulnerability scanner to an active, behavioral HIDS capable of catching zero-day supply chain attacks that actively try to hide.

1.  **L1 - Allowlist Enforcer:** Stops unauthorized registry communication.
2.  **L2 - Domain Reputation:** Catches newly registered or low-reputation C2 domains.
3.  **L3 - DNS Anomalies:** Detects Fast-Flux and DGA evasion tactics.
4.  **L4 - Raw IP Connections:** Flags hardcoded IP addresses bypassing DNS.
5.  **L5 - Process Escapes:** Intercepts attempts to spawn shells or execute LotL commands.

*This document serves as the formal research documentation for the evasion detection capabilities developed during the final stage of the internship.*
