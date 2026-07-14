# Supply Chain Sentinel — Production Architecture

This document illustrates how Supply Chain Sentinel is deployed in a real-world enterprise Kubernetes environment. Rather than running locally on a developer's laptop, the tool shifts into a distributed, centralized model (Clean Architecture).

## 1. High-Level Production Flow

The architecture follows a strict separation of concerns:
1. **Data Collection (Edge):** The DaemonSet agents running on every node.
2. **Data Processing (Core):** The Central API / SIEM that aggregates alerts and calculates risk.
3. **Presentation (User):** The SOC Analyst Dashboard.

```mermaid
graph TD
    classDef k8s fill:#326ce5,stroke:#fff,stroke-width:2px,color:#fff;
    classDef agent fill:#ff9800,stroke:#fff,stroke-width:2px,color:#fff;
    classDef siem fill:#4caf50,stroke:#fff,stroke-width:2px,color:#fff;
    classDef user fill:#9c27b0,stroke:#fff,stroke-width:2px,color:#fff;
    
    subgraph "Kubernetes Cluster (Production Environment)"
        subgraph "Worker Node 1"
            P1[App Pod A]
            P2[App Pod B]
            D1[Sentinel DaemonSet Agent]:::agent
            
            P1 -.->|Process & Network Telemetry| D1
            P2 -.->|Process & Network Telemetry| D1
        end

        subgraph "Worker Node 2"
            P3[App Pod C]
            D2[Sentinel DaemonSet Agent]:::agent
            
            P3 -.->|Process & Network Telemetry| D2
        end
    end
    
    subgraph "Centralized Security Platform (SIEM / Aggregator)"
        S1[Logstash / FluentBit Pipeline]:::siem
        S2[(Security Data Lake / Elasticsearch)]:::siem
        S3[Threat Detection Engine]:::siem
        
        D1 ===>|Push Raw Telemetry & 1-100 Scores| S1
        D2 ===>|Push Raw Telemetry & 1-100 Scores| S1
        S1 --> S2
        S2 --> S3
    end
    
    subgraph "Security Operations (SOC)"
        U1[Kibana / Datadog Dashboard]:::user
        U2[PagerDuty / Slack Alerts]:::user
        U3((Security Engineer)):::user
        
        S3 -->|Alert if Score >= 50| U2
        S2 -->|Visualization| U1
        U2 -->|Action Required| U3
        U1 -.->|Investigate| U3
    end
```

## 2. Component Breakdown

### A. The DaemonSet Agents (Data Collectors)
In Kubernetes, you deploy the Sentinel not as an app pod, but as a privileged **DaemonSet**. 
* **Placement:** Kubernetes guarantees exactly one Sentinel container runs on every single worker node.
* **Role:** It mounts the node's Docker/Containerd socket. It uses `monitor.py --watch` to monitor all other pods on that same node. It generates the `Package Threat Score (1-100)` and detects the 5 layers of evasion (DNS, Process Escapes, etc.).

### B. The Centralized SIEM (Data Aggregator)
The Sentinel agents do not store logs locally in production. Instead, they stream their findings (JSON payloads) to a centralized Security Information and Event Management (SIEM) system like Elastic Security, Datadog, or Splunk.
* **Role:** It stores all historical telemetry across the entire cluster. It allows engineers to search for IOCs (Indicators of Compromise) globally.

### C. The SOC User (Action Taker)
The end-user is a Security Engineer or DevSecOps professional.
* **Role:** They receive an automated Slack or PagerDuty alert triggered by the SIEM if any package crosses the `50` (Malicious) threshold. They review the Sentinel's deep-scan data on their dashboard and decide whether to quarantine the affected Kubernetes node or block the malicious package.

## 3. The CI/CD Pipeline (Pre-Deployment)

*Note: While the DaemonSet monitors runtime, Sentinel is also typically embedded in the CI/CD pipeline as an Admission Controller.*

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant CI as GitHub Actions
    participant Sentinel as Sentinel Pipeline Scanner
    participant K8s as Kubernetes Cluster
    
    Dev->>CI: Git Push (New App Version)
    CI->>Sentinel: Trigger Static Image Scan
    Sentinel->>Sentinel: Generate SBOM & Query OSV
    Sentinel->>Sentinel: Deep Static Artifact Scan
    
    alt Threat Score >= 50
        Sentinel-->>CI: FAIL BUILD
        CI-->>Dev: Alert: Malicious Package Detected!
    else Threat Score < 50
        Sentinel-->>CI: PASS
        CI->>K8s: Deploy Application
        K8s->>K8s: Sentinel DaemonSet begins Runtime Watch
    end
```
