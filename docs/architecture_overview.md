# AI-Powered Incident Analysis: Architecture Overview

## Summary

This system implements a multi-stage AI agent architecture that combines traditional data processing with Generative AI agentic patterns to analyze security incidents and prioritize CVE vulnerabilities. The architecture demonstrates multiple complementary strategies:

1. **Traditional Parsing**: Structured incident data extraction without LLM overhead
2. **Targeted AI Enhancement**: CPE generation using smaller, focused LLM operations
3. **Intelligent Pre-processing**: Automated vulnerability discovery and correlation
4. **Agentic Research & Analysis**: Advanced LLM reasoning with tool orchestration

## System Architecture Overview

```mermaid
graph TB
    subgraph "Input Layer"
        A[Incident Data JSON] --> B[Incident Parser]
    end
    
    subgraph "Enhancement Layer"
        B --> C[CPE Extraction Stage]
        C --> D[Incident Pre-processing Stage]
    end
    
    subgraph "AI Agent Layer"
        D --> E[Research Stage]
        E --> F[Analysis Stage]
    end
    
    subgraph "Output Layer"
        F --> G[Report Generation Stage]
        G --> H[Technical Report]
        G --> I[Customer Report]
    end
    
    subgraph "Supporting Infrastructure"
        J[NVD API Tools]
        K[MCP Clients]
        L[Context Management]
        M[Token Management]
        N[Validation Framework]
    end
    
    C -.-> J
    D -.-> J
    E -.-> J
    E -.-> K
    F -.-> K
    
    E -.-> L
    F -.-> L
    E -.-> M
    F -.-> M
    
    C -.-> N
    E -.-> N
    F -.-> N
    
    style A fill:#e1f5fe
    style H fill:#c8e6c9
    style I fill:#c8e6c9
    style E fill:#fff3e0
    style F fill:#fff3e0
```

## Multi-Phase Processing Pipeline

### Phase 1: Efficient Non-AI Parsing
**Purpose**: Extract structured data without LLM costs
**Implementation**: Traditional JSON parsing with validation

```mermaid
graph LR
    A[Raw Incident JSON] --> B[Schema Validation]
    B --> C[Data Model Creation]
    C --> D[Asset Extraction]
    C --> E[TTP Extraction]
    C --> F[IOC Extraction]
    
    style A fill:#ffebee
    style D fill:#e8f5e8
    style E fill:#e8f5e8
    style F fill:#e8f5e8
```

### Phase 2: Targeted CPE Enhancement
**Purpose**: Generate precise vulnerability identifiers using focused AI
**Implementation**: Batch processing with smaller LLM for efficiency

```mermaid
graph TB
    A[Parsed Incidents] --> B[Asset & Software Analysis]
    B --> C[CPE Generation LLM]
    C --> D[CPE Validation]
    D --> E[Enhanced Incident Data]
    
    subgraph "CPE Generation Process"
        F[Batch Assets] --> G[Generate CPE Strings]
        G --> H[Validate Format]
        H --> I[Cross-reference Assets]
        I --> J[Apply to Incident]
    end
    
    C --> F
    J --> E
    
    style C fill:#fff3e0
    style E fill:#e8f5e8
```

### Phase 3: Intelligent Vulnerability Pre-processing
**Purpose**: Create comprehensive vulnerability baseline using CPE data
**Implementation**: Automated NVD correlation with contextual filtering

```mermaid
graph TB
    A[Enhanced Incident Data] --> B[Extract Unique Software]
    B --> C[CPE-based CVE Search]
    C --> D[Keyword-based CVE Search]
    D --> E[Relevance Scoring]
    E --> F[Temporal Filtering]
    F --> G[Vulnerability Report]
    
    subgraph "NVD Integration"
        H[NVD API] --> C
        H --> D
        I[CPE Matching] --> C
        J[Version Analysis] --> E
        K[CVSS Scoring] --> E
    end
    
    style G fill:#e8f5e8
    style H fill:#e1f5fe
```

### Phase 4: Agentic Research & Analysis
**Purpose**: Advanced reasoning and contextual analysis
**Implementation**: Multi-stage LLM agents with tool orchestration

```mermaid
graph TB
    A[Vulnerability Report] --> B[Research Agent]
    B --> C[Analysis Agent]
    
    subgraph "Research Stage"
        D[Research Planning] --> E[Tool Selection]
        E --> F[Information Gathering]
        F --> G[Synthesis & Validation]
    end
    
    subgraph "Analysis Stage"
        H[Context Analysis] --> I[Risk Assessment]
        I --> J[Prioritization]
        J --> K[Recommendation Generation]
    end
    
    B --> D
    C --> H
    
    subgraph "Tool Ecosystem"
        L[NVD Tools]
        M[MCP Clients]
        N[Submission Tools]
    end
    
    E -.-> L
    E -.-> M
    G -.-> N
    K -.-> N
    
    style B fill:#fff3e0
    style C fill:#fff3e0
```

## Agentic Stage Architecture

```mermaid
graph TB
    subgraph "AgenticStageBase Framework"
        A[LLM Factory] --> B[Tool Manager]
        B --> C[Loop Controller]
        C --> D[Error Recovery]
        D --> E[Context Manager]
    end
    
    subgraph "Stage Execution Flow"
        F[Initial Messages] --> G[LLM + Tools]
        G --> H[Tool Execution]
        H --> I[Validation]
        I --> J{Terminate?}
        J -->|No| K[Continue Loop]
        J -->|Yes| L[Final Result]
        K --> G
    end
    
    subgraph "Supporting Systems"
        M[Token Management]
        N[Context Compression]
        O[Validation Framework]
    end
    
    B --> F
    C --> G
    E --> N
    I --> O
    G -.-> M
    
    style G fill:#fff3e0
    style L fill:#c8e6c9
```

## Tool Integration Architecture

```mermaid
graph TB
    subgraph "Tool Categories"
        A[NVD API Tools]
        B[Submission Tools]
        C[CPE Generation Tools]
        D[MCP Client Tools]
    end
    
    subgraph "Tool Management"
        E[Tool Registry] --> F[Tool Binding]
        F --> G[Execution Manager]
        G --> H[Validation Layer]
    end
    
    subgraph "LLM Integration"
        I[LLM with Tools] --> J[Tool Call Detection]
        J --> K[Argument Injection]
        K --> L[Tool Execution]
        L --> M[Result Processing]
    end
    
    A --> E
    B --> E
    C --> E
    D --> E
    
    F --> I
    G --> L
    H --> M
    
    style I fill:#fff3e0
    style M fill:#c8e6c9
```

## Data Flow & Validation

```mermaid
graph LR
    subgraph "Input Validation"
        A[Raw Data] --> B[Schema Check]
        B --> C[Business Rules]
        C --> D[Sanitization]
    end
    
    subgraph "Processing Validation"
        E[Stage Input] --> F[Tool Validation]
        F --> G[Output Validation]
        G --> H[Cross-Reference Check]
    end
    
    subgraph "Output Validation"
        I[Analysis Result] --> J[Completeness Check]
        J --> K[Consistency Check]
        K --> L[Quality Metrics]
    end
    
    D --> E
    H --> I
    L --> M[Validated Output]
    
    style M fill:#c8e6c9
```

## Context & Token Management

```mermaid
graph TB
    subgraph "Context Window Management"
        A[Message History] --> B[Token Counting]
        B --> C{Exceeds Threshold?}
        C -->|Yes| D[Compression Strategy]
        C -->|No| E[Continue Processing]
        D --> F[Intelligent Compression]
        D --> G[Simple Truncation]
        F --> E
        G --> E
    end
    
    subgraph "Token Budget Management"
        I[Stage Budgets]
        I --> J[Usage Tracking]
        J --> K[Cost Estimation]
    end
    
    B --> J
    E --> L[Optimized Context]
    
    style L fill:#c8e6c9
```

## Key Architectural Advantages

### 1. **Efficiency Through Strategy Combination**
- **Non-AI parsing**: Eliminates unnecessary LLM costs for structured data
- **Targeted AI enhancement**: Uses smaller models for specific tasks (CPE generation)
- **Intelligent pre-processing**: Reduces agent workload through automated correlation
- **Focused agentic reasoning**: Applies expensive LLM operations only where advanced reasoning is needed

### 2. **Production-Ready Robustness**
- **Comprehensive error recovery**: Multiple fallback strategies at each stage
- **Validation framework**: Ensures data integrity throughout the pipeline
- **Context management**: Handles real-world token limitations
- **Monitoring & observability**: Token tracking, performance metrics, error logging

### 3. **Scalable Architecture**
- **Modular design**: Each stage can be independently scaled or modified
- **Configurable LLMs**: Different models for different stages based on requirements
- **Batch processing**: Efficient handling of multiple incidents
- **Resource optimization**: Token budgets and context compression

### 4. **Advanced Agentic Patterns**
- **Tool orchestration**: Dynamic tool selection and execution
- **Iterative reasoning**: Multi-turn conversations with validation
- **Structured outputs**: Pydantic models ensure consistent results
- **Explainable AI**: Complete reasoning chains and tool usage logs

This architecture demonstrates a sophisticated understanding of when and how to apply different AI strategies, combining efficiency with advanced reasoning capabilities to create a production-ready incident analysis system.