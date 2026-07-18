# Live Runtime Monitoring & Evasion Detection (HIDS)

[Back to Main README](../README.md)

This document describes the Host-based Intrusion Detection System (HIDS) capabilities, monitoring the container at runtime for malicious behavior and evasion techniques.

## Runtime Monitoring Architecture

```mermaid
flowchart TD
    classDef container fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef monitor fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef evasion fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px,color:#000
    classDef output fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000

    CONT[Running Container]:::container --> SCANNER[Runtime Package Scanner<br/>docker diff / eBPF]:::monitor
    
    SCANNER --> FS[File Change Detection<br/>Added/Modified/Deleted]:::monitor
    FS -- "New files fed back to pipeline" --> AST_AI[AST + AI Pipeline]:::monitor
    
    SCANNER --> NET[Network Monitoring<br/>TCP/UDP Sockets]:::monitor
    NET --> EVASION[5-Layer Evasion Detection]:::evasion
    
    EVASION --> L1[L1: Allowlist]:::evasion
    EVASION --> L2[L2: Domain Age]:::evasion
    EVASION --> L3[L3: DNS Tunneling]:::evasion
    EVASION --> L4[L4: Raw IP]:::evasion
    EVASION --> L5[L5: Process Escapes]:::evasion
    
    L1 --> ALERT[Alert Generation]:::output
    L2 --> ALERT
    L3 --> ALERT
    L4 --> ALERT
    L5 --> ALERT
```

## Implementation Approaches: PoC vs. Production

Supply Chain Sentinel's runtime monitoring can be deployed in two modes depending on the environment:

### Proof of Concept (PoC) Approach
*   **Mechanism**: Uses standard Docker CLI commands (`docker diff`, `docker exec`).
*   **Pros**: Highly portable, requires zero host-level configuration, works on any machine with the Docker daemon, requires no elevated kernel privileges.
*   **Cons**: Polling-based approach introduces slight latency. Misses ephemeral processes that start and die between polling intervals.

### Production Approach
*   **Mechanism**: Utilizes eBPF (Extended Berkeley Packet Filter) and direct OverlayFS monitoring.
*   **Pros**: Kernel-level visibility. Event-driven rather than polling, meaning zero-latency detection. Captures ephemeral processes and provides deep insight into syscalls.
*   **Cons**: Requires root/CAP_SYS_ADMIN privileges on the host. Kernel version dependencies. More complex deployment model.
