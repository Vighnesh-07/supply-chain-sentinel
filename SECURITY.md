# Security Policy

Supply Chain Sentinel is a cybersecurity tool designed to protect software supply chains. We take the security of this project and its users extremely seriously. This document outlines our security policy and provides instructions for reporting vulnerabilities.

---

## Supported Versions

The following versions of Supply Chain Sentinel receive security updates:

| Version | Status              | Support Level         |
|---------|---------------------|-----------------------|
| 1.x     | **Current release** | Full security support |
| 0.9.x   | Previous release    | Critical patches only |
| < 0.9   | End of life         | No support            |

> Only the latest minor release within each supported major version receives patches. Users are strongly encouraged to upgrade to the latest version.

---

## Reporting a Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

If you discover a security vulnerability in Supply Chain Sentinel, please report it responsibly through one of the following channels:

### Preferred: GitHub Private Vulnerability Reporting

1. Navigate to the **Security** tab of this repository.
2. Click **"Report a vulnerability"**.
3. Complete the form with as much detail as possible.

### Alternative: Email

Send a detailed report to: **security@supplychainsentinel.dev**

Use the PGP key published at the root of this repository (`SECURITY_PGP.asc`) to encrypt sensitive communications if needed.

### What to Include

Please provide the following information to help us triage and resolve the issue quickly:

- **Description** -- A clear summary of the vulnerability.
- **Attack vector** -- How the vulnerability can be exploited.
- **Impact** -- What an attacker could achieve (data exfiltration, privilege escalation, etc.).
- **Affected components** -- Specific modules, functions, or endpoints involved.
- **Reproduction steps** -- Detailed, step-by-step instructions to reproduce the issue.
- **Proof of concept** -- Code, scripts, or screenshots demonstrating the vulnerability (if available).
- **Suggested fix** -- Your recommended remediation, if any.
- **Environment** -- OS, Python version, package version, and relevant configuration.

---

## Response Timeline

We are committed to addressing security reports promptly:

| Stage                     | Target Timeframe     |
|---------------------------|----------------------|
| Acknowledgment of report  | Within 48 hours      |
| Initial triage             | Within 5 business days |
| Status update to reporter | Every 7 days         |
| Patch development          | Depends on severity  |
| Public disclosure          | After patch release  |

### Severity-Based Patch Targets

| Severity | CVSS Score | Patch Target        |
|----------|------------|---------------------|
| Critical | 9.0 -- 10.0  | Within 72 hours     |
| High     | 7.0 -- 8.9   | Within 7 days       |
| Medium   | 4.0 -- 6.9   | Within 30 days      |
| Low      | 0.1 -- 3.9   | Next scheduled release |

---

## Security Update Policy

- **Patch releases** are issued for critical and high-severity vulnerabilities as soon as a fix is verified.
- **Security advisories** are published via [GitHub Security Advisories](https://github.com/Vighnesh/supply-chain-sentinel/security/advisories) once a patch is available.
- All security patches are accompanied by a changelog entry and a CVE identifier (when applicable).
- Users subscribed to repository notifications will receive alerts for security releases.

### Dependency Management

Supply Chain Sentinel monitors its own dependencies for known vulnerabilities using automated tooling. Dependency updates for security issues are prioritized and released promptly.

---

## Responsible Disclosure

We follow a coordinated disclosure process:

1. **Reporter submits** the vulnerability through a private channel.
2. **We acknowledge** receipt and begin triage.
3. **We develop and test** a fix in a private branch.
4. **We release** the patched version and publish a security advisory.
5. **Public disclosure** occurs only after the fix is available to users.

We request that reporters:

- **Allow us reasonable time** to investigate and address the issue before any public disclosure.
- **Do not exploit** the vulnerability beyond what is necessary to demonstrate it.
- **Do not access, modify, or delete** data belonging to other users.
- **Act in good faith** to avoid privacy violations, service disruption, or data destruction.

We will:

- **Credit reporters** in the security advisory (unless anonymity is requested).
- **Not pursue legal action** against researchers who follow this policy.
- **Work collaboratively** with reporters to understand and resolve the issue.

---

## Scope

This security policy applies to:

- The Supply Chain Sentinel source code and releases in this repository.
- Official container images and distribution packages.
- Documentation and configuration examples that may affect security posture.

This policy does **not** cover:

- Third-party integrations or plugins not maintained by this project.
- Vulnerabilities in upstream dependencies (report these to the respective maintainers).
- Social engineering attacks against project maintainers.

---

## Contact

For security-related inquiries: **security@supplychainsentinel.dev**

For general questions: Open a [Discussion](https://github.com/Vighnesh/supply-chain-sentinel/discussions) on GitHub.
