# System Overview - Complete Architecture

> **Supply Chain Sentinel** -- End-to-end software supply chain security analysis pipeline.

[![Back to README](https://img.shields.io/badge/Back_to-README-blue?style=flat-square)](../README.md)

---

## High-Level Pipeline

The following diagram illustrates the complete processing pipeline from a Docker image input through six distinct analysis stages to the final consolidated output.

```mermaid
flowchart TD
    subgraph INPUT["INPUT STAGE"]
        A["Docker Image\n(local or remote registry)"]
    end

    subgraph SBOM["STAGE 1 -- SBOM GENERATION"]
        B["Syft Scanner"]
        C["CycloneDX JSON\nBOM Output"]
        B --> C
    end

    subgraph DRIFT["STAGE 2 -- VERSION DRIFT"]
        D["Registry API Clients\n(PyPI / npm / RubyGems / Go)"]
        E["Version Comparator\nSemVer + Staleness Check"]
        D --> E
    end

    subgraph VULN["STAGE 3 -- VULNERABILITY SCAN"]
        F["OSV.dev API\nBatch Query"]
        G["CVSS v3.1 Decoder\n(FIRST.org Formula)"]
        H["Per-CVE Severity\nClassification"]
        F --> G --> H
    end

    subgraph THREAT["STAGE 4 -- THREAT INTELLIGENCE"]
        I["OSV MAL- Advisories"]
        J["GitHub Advisory\n(GHSA-)"]
        K["Local Blocklist\nKnown-Malicious DB"]
        L["Typosquat Detector\nLevenshtein Distance"]
    end

    subgraph STATIC["STAGE 5 -- DEEP STATIC ANALYSIS"]
        M["AST Scanner\n(Tree-sitter)"]
        N["Regex Pattern Engine\n(Secrets / Payloads)"]
        O["Gemini AI\nIntent Verification"]
        M --> O
        N --> O
    end

    subgraph RUNTIME["STAGE 6 -- RUNTIME MONITORING"]
        P["Docker diff Polling\nFile Change Detection"]
        Q["Network Socket\nExtraction"]
        R["5-Layer Evasion\nDetection Engine"]
        P --> R
        Q --> R
    end

    subgraph OUTPUT["OUTPUT STAGE"]
        S["Terminal Dashboard\n(Rich / Textual)"]
        T["Excel Report\n(.xlsx with Severity Sheets)"]
    end

    A --> B
    C --> D
    C --> F
    C --> I & J & K & L
    C --> M & N
    A --> P & Q
    E --> S & T
    H --> S & T
    I & J & K & L --> S & T
    O --> S & T
    R --> S & T

    classDef inputStyle fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#eee
    classDef sbomStyle fill:#16213e,stroke:#0f3460,stroke-width:2px,color:#eee
    classDef driftStyle fill:#1b262c,stroke:#0f4c75,stroke-width:2px,color:#eee
    classDef vulnStyle fill:#2d132c,stroke:#c72c41,stroke-width:2px,color:#eee
    classDef threatStyle fill:#1c0c1c,stroke:#6c3483,stroke-width:2px,color:#eee
    classDef staticStyle fill:#0c2233,stroke:#1abc9c,stroke-width:2px,color:#eee
    classDef runtimeStyle fill:#1a1a0e,stroke:#f39c12,stroke-width:2px,color:#eee
    classDef outputStyle fill:#0d3b0d,stroke:#27ae60,stroke-width:2px,color:#eee

    class A inputStyle
    class B,C sbomStyle
    class D,E driftStyle
    class F,G,H vulnStyle
    class I,J,K,L threatStyle
    class M,N,O staticStyle
    class P,Q,R runtimeStyle
    class S,T outputStyle
```

---

## Stage Descriptions

| # | Stage | Purpose | Key Technology |
|---|-------|---------|----------------|
| 0 | **Input** | Accept a Docker image (local tag or remote registry reference) as the sole entry point. | `docker`, OCI registries |
| 1 | **SBOM Generation** | Extract every software component embedded in the image filesystem layers. | [Syft](https://github.com/anchore/syft), CycloneDX JSON |
| 2 | **Version Drift Check** | Compare each discovered package version against the latest published version in its upstream registry. Flag stale or yanked releases. | PyPI JSON API, npm Registry, RubyGems API, Go Proxy |
| 3 | **Vulnerability Scan** | Query every package/version pair against the OSV.dev vulnerability database. Decode CVSS v3.1 vector strings to compute base scores and classify severity. | [OSV.dev](https://osv.dev), FIRST.org CVSS v3.1 |
| 4 | **Threat Intelligence** | Cross-reference packages against four independent malicious-package databases and detection heuristics running in parallel. | OSV MAL-, GHSA, Blocklist, Levenshtein |
| 5 | **Deep Static Analysis** | Extract package source code from the image, parse it with language-aware AST scanners, match suspicious patterns with regex, then send compact code snippets to Gemini AI for intent verification. | Tree-sitter, Regex, Google Gemini API |
| 6 | **Runtime Monitoring** | Start the container and monitor filesystem mutations and network activity in real time. Apply a 5-layer evasion detection engine to outbound connections. | `docker diff`, `docker exec`, TCP/UDP socket inspection |
| 7 | **Output** | Consolidate all findings into a colour-coded terminal dashboard and a multi-sheet Excel report with per-CVE, per-package, and summary tabs. | Rich / Textual, openpyxl |

---

## Data Flow Summary

1. A single **Docker image** enters the pipeline.
2. **Syft** produces a machine-readable **CycloneDX BOM** listing every component.
3. That BOM fans out to **four parallel analysis tracks**: version drift, vulnerability scanning, threat intelligence, and static analysis.
4. Independently, the **running container** is monitored for runtime anomalies.
5. All six tracks converge into a unified **findings model** that feeds both the terminal dashboard and the Excel report.

> [!NOTE]
> Each stage is designed to operate independently so that failures in one track (e.g., a registry API timeout) do not block the remaining analyses. Results are merged at the output stage with clear provenance indicating which engine flagged each finding.

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [SBOM & Vulnerability Scanning](./02-sbom-and-vulnerability.md) | Deep dive into SBOM parsing and CVSS decoding |
| [Threat Intelligence Engine](./03-threat-intelligence.md) | Multi-database threat correlation |
| [Static Analysis & AI](./04-static-analysis-and-ai.md) | AST scanning, regex patterns, and Gemini AI verification |
| [Runtime Monitoring](./05-runtime-monitoring.md) | Live container monitoring and evasion detection |
