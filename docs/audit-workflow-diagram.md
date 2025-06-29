# GHAS Audit Workflow Architecture

## Overview
This diagram illustrates the end-to-end GitHub Advanced Security audit automation workflow for compliance reporting.

## Workflow Diagram

```mermaid
flowchart TB
    %% Styling
    classDef github fill:#0366d6,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef repo fill:#28a745,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef workflow fill:#f6f8fa,stroke:#24292e,stroke-width:2px,color:#24292e
    classDef engine fill:#ff6b6b,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef api fill:#6f42c1,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef compliance fill:#fd7e14,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef output fill:#4ecdc4,stroke:#ffffff,stroke-width:2px,color:#ffffff
    classDef deliverable fill:#ffd93d,stroke:#24292e,stroke-width:2px,color:#24292e

    %% Main Flow
    A[🏢 GitHub Organization] --> B[📦 GHAS Audit Demo Repo]
    B --> C[⚡ GitHub Actions Workflow]

    %% Audit Engine
    C --> D[🔍 Audit Engine]
    D --> E[🔌 GitHub APIs]

    %% Data Collection
    E --> F[🔒 CodeQL Alerts]
    E --> G[🔑 Secret Scanning]
    E --> H[📦 Dependabot Alerts]

    %% Compliance Processing
    D --> I[📋 Compliance Engine]
    I --> J[🛡️ OWASP Top 10]
    I --> K[🏛️ NIST Framework]
    I --> L[📊 ISO 27001]

    %% Risk Assessment
    D --> M[⚖️ Risk Assessment]
    M --> N[🚨 Severity Analysis]
    M --> O[📈 Repository Scoring]

    %% Report Generation
    D --> P[📊 Report Generation]
    P --> Q[📄 JSON Audit Report]
    P --> R[📋 Executive Dashboard]

    %% Visualizations
    R --> S[📊 Chart.js Visualizations]
    S --> T[🥧 Severity Distribution]
    S --> U[📊 Alert Types]
    S --> V[🎯 Compliance Scores]

    %% Executive Output
    R --> W[📋 Executive Summary]
    R --> X[💡 Risk Recommendations]

    %% Artifacts
    Q --> Y[📦 GitHub Artifacts]
    R --> Y

    %% Final Deliverable
    Y --> Z[🎓 Student Lab Deliverable]

    %% Apply Styling
    class A github
    class B repo
    class C workflow
    class D engine
    class E,F,G,H api
    class I,J,K,L compliance
    class M,N,O workflow
    class P,Q,R output
    class S,T,U,V output
    class W,X output
    class Y,Z deliverable

    %% Subgraph for better organization
    subgraph "Data Collection Layer"
        F
        G
        H
    end

    subgraph "Compliance Framework Mapping"
        J
        K
        L
    end

    subgraph "Risk Analysis"
        N
        O
    end

    subgraph "Visualization Layer"
        T
        U
        V
    end

    subgraph "Executive Output"
        W
        X
    end
```

## Key Components

### 🔍 **Audit Engine**
- **Core processing** for security data collection
- **API integration** with GitHub Advanced Security
- **Risk calculation** and scoring algorithms

### 📋 **Compliance Engine**
- **OWASP Top 10** vulnerability mapping
- **NIST Cybersecurity Framework** alignment
- **ISO 27001** control mapping

### 📊 **Report Generation**
- **JSON structured data** for programmatic access
- **Executive dashboard** with interactive charts
- **Compliance evidence** for audit readiness

### 🎯 **Student Deliverables**
- **Forkable template** for hands-on learning
- **Customizable workflow** for different organizations
- **Production-ready** audit automation

## Usage Notes

- **Update organization name** in workflow configuration
- **Modify compliance mappings** as frameworks evolve
- **Add new visualization types** as needed
- **Extend API integrations** for additional tools

## Color Legend

- 🔵 **GitHub** - Source systems and repositories
- 🟢 **Repository** - Template and configuration
- 🔴 **Engine** - Core processing components
- 🟣 **API** - Data collection interfaces
- 🟠 **Compliance** - Framework alignment
- 🔵 **Output** - Reports and visualizations
- 🟡 **Deliverable** - Student lab artifacts

---

*Last Updated: 2024-01-XX*
*Maintainer: Tim Warner - Pluralsight GHAS Course*
