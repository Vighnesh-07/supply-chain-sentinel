# Multi-Database Threat Intelligence Engine

[Back to Main README](../README.md)

This document outlines the Threat Intelligence engine, which cross-references identified dependencies against multiple security databases and heuristics to detect malicious packages.

## Threat Intelligence Architecture

```mermaid
flowchart TD
    classDef input fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef check fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef logic fill:#e8eaf6,stroke:#283593,stroke-width:2px,color:#000
    classDef output fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    PKG[Package List]:::input
    
    PKG --> C1[OSV MAL- Advisories]:::check
    PKG --> C2[GitHub Advisory GHSA]:::check
    PKG --> C3[Local Blocklist]:::check
    PKG --> C4[Typo-squatting Check<br/>Levenshtein distance]:::check
    
    C1 --> DECISION[Decision Logic Engine]:::logic
    C2 --> DECISION
    C3 --> DECISION
    C4 --> DECISION
    
    DECISION -- "Match found in MAL- or Blocklist" --> FLAG_MAL[Flag: MALICIOUS]:::output
    DECISION -- "Match found in GHSA" --> FLAG_ADV[Flag: ADVISORY]:::output
    DECISION -- "No matches, high Levenshtein score" --> FLAG_CLEAN[Flag: CLEAN]:::output
    
    FLAG_MAL --> REP[Threat Intelligence Report]:::output
    FLAG_ADV --> REP
    FLAG_CLEAN --> REP
```

## Databases and Detection Techniques

| Technique / Database | Description | Target Threat |
| :--- | :--- | :--- |
| **OSV MAL- Advisories** | Queries the Open Source Vulnerabilities database specifically for "MAL-" prefixes. | Known malicious packages and supply chain attacks. |
| **GHSA** | GitHub Security Advisories database integration. | Vulnerabilities and security advisories reported in GitHub. |
| **Local Blocklist** | An internal, customizable list of known bad package names, hashes, or author signatures. | Zero-day threats and organization-specific banned packages. |
| **Typo-squatting Detection** | Calculates Levenshtein distance against the top 10,000 most popular packages. | Packages masquerading as popular libraries (e.g., `reqeusts` instead of `requests`). |
