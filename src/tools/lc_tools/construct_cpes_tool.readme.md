# CPE Construction Tool

## Overview

Automated system to generate CPE (Common Platform Enumeration) strings from security incident data using LLMs. Designed for scalable processing of large incident datasets while optimizing for cost and accuracy.

## Architecture

### Core Pipeline
1. **Data Extraction** - Extract asset information (hostname, OS, software) from incidents
2. **Smart Batching** - Group similar assets into optimally-sized batches for LLM processing
3. **LLM Processing** - Generate CPE strings using configured language model
4. **Validation** - Verify CPE format and semantic correctness
5. **Results Output** - Return validated CPE mappings with confidence scores

### Key Design Principles
- **Batch Optimization**: Process multiple assets per LLM call to minimize API costs
- **Quality Assurance**: Multi-stage validation ensures CPE accuracy
- **Scalability**: Handle hundreds to thousands of incidents efficiently
- **Flexibility**: Configurable for different LLM providers and capabilities

## Implementation Phases

### Current (MVP)
**Target**: Process ~100 incidents using local Ollama models

**Core Components**:
- Basic data extraction from incident JSON
- Simple batching (fixed batch sizes)
- Ollama integration for local LLM processing
- Basic CPE format validation
- JSON output with asset-to-CPE mappings

**Scope Limitations**:
- Local processing only (no API costs)
- Fixed batch sizes
- Basic error handling
- Manual configuration

### Phase 2 (Future Enhancement)
**Target**: Production-scale processing with advanced features

**Additional Components**:
- Intelligent similarity-based batching
- Multi-model support (API providers)
- Advanced validation and confidence scoring
- Caching and deduplication
- Performance monitoring and metrics
- Distributed processing capabilities
- Automated batch size optimization
- Error recovery and retry logic

## Technical Requirements

### MVP Requirements
- Python environment with LangChain
- Local Ollama installation
- JSON input/output handling
- Basic CPE validation logic

### Phase 2 Requirements
- API integration capabilities
- Caching infrastructure
- Monitoring and logging systems
- Distributed processing framework