# Deep Static Analysis & AI Intent Verification

[Back to Main README](../README.md)

This document explains the 'Funnel Architecture' used for static code analysis, ending with an AI-driven intent verification step.

## Funnel Architecture Diagram

```mermaid
flowchart TD
    classDef input fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef static fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef filter fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px,color:#000
    classDef ai fill:#e8eaf6,stroke:#283593,stroke-width:2px,color:#000
    classDef logic fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000
    classDef output fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    SRC[Package Source Code<br/>docker cp]:::input --> AST[AST Scanner<br/>Tree-sitter: Python, JS, Go, Ruby]:::static
    AST --> REGEX[Regex Pattern Matching]:::static
    
    REGEX -- "Base64 payloads, eval/exec,<br/>env vars, hardcoded IPs,<br/>crypto wallets, Shannon entropy secrets" --> EXTRACT[Extract Suspicious Snippets<br/>5-10 lines per flag]:::filter
    
    EXTRACT --> GEMINI[Gemini AI Analysis]:::ai
    GEMINI -- "Returns: verdict, confidence, intent_summary" --> OVERRIDE[False Positive Override Logic]:::logic
    OVERRIDE --> OUT[Final Threat Classification]:::output
```

## The AI Funnel Approach

Rather than sending entire codebases to the AI, Supply Chain Sentinel utilizes a "Funnel Architecture".

### Why we don't send full code to the AI:
1.  **Cost**: Large Language Model APIs charge based on token count. Sending thousands of lines of benign code for every package is financially unscalable.
2.  **Context Window (Tokens)**: Models have maximum token limits. Large packages would exceed these limits, requiring complex chunking strategies that break semantic context.
3.  **Speed**: Processing massive prompts takes significantly longer. By isolating 5-10 lines of highly suspicious code via AST and Regex first, the AI can perform a micro-analysis in milliseconds.

The traditional static tools (AST/Regex) act as the wide end of the funnel, catching all potential anomalies. The AI sits at the narrow end, providing high-fidelity intent analysis (e.g., distinguishing between a legitimate administrative tool using `eval()` versus a malicious backdoor) to drastically reduce false positives.
