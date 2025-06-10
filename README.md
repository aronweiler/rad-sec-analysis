# RAD Security Analysis

An AI-powered incident analysis system that combines traditional data processing with Generative AI agentic patterns to analyze security incidents and prioritize CVE vulnerabilities.

## Overview

This system implements a multi-stage AI agent architecture that processes security incident data through several phases:

1. **Traditional Parsing**: Structured incident data extraction without LLM overhead
2. **Targeted AI Enhancement**: CPE generation using smaller, focused LLM operations  
3. **Intelligent Pre-processing**: Automated vulnerability discovery and correlation
4. **Agentic Research & Analysis**: Advanced LLM reasoning with tool orchestration

## Prerequisites

Before running this application, you need to have the following components set up:

### 1. Vulnerability Intelligence MCP Server

This application requires the Vulnerability Intelligence MCP server to be running. The MCP server provides security vulnerability intelligence tools including CVE lookup, EPSS scoring, and exploit detection.

#### Quick Setup with Docker (Recommended)

```bash
# Clone the MCP server repository
git clone https://github.com/firetix/vulnerability-intelligence-mcp-server
cd vulnerability-intelligence-mcp-server

# Create environment file
cp .env.example .env

# Build and start the server
docker compose up --build -d

# Verify the server is running
docker compose ps
```

The MCP server will be available at: `http://localhost:8000/sse`

#### Alternative: Use Hosted Server

You can also use the pre-hosted server at: `https://vulnerability-intelligence-mcp-server-edb8b15494e8.herokuapp.com/sse`

### 2. Python Environment

- Python 3.12 or higher
- Virtual environment (recommended)

### 3. API Keys

You'll need API keys for the following services:
- **Anthropic API Key** - For Claude AI models
- **OpenAI API Key** - For OpenAI models  
- **NVD API Key** - For National Vulnerability Database access (not required, but you will face higher rate limits)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/aronweiler/rad-sec-analysis.git
cd rad-sec-analysis
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

```bash
# Copy the environment template
cp .env.template .env
```

Edit the `.env` file and populate the following variables:

```env
ANTHROPIC_API_KEY=your_anthropic_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
NVD_API_KEY=your_nvd_api_key_here
```

### 5. Prepare Incident Data

Place your incident data file in the project directory. The default expected file is `data/incident_data.json`, but you can specify a different file using the `--file` parameter.

## Usage

### Basic Usage

```bash
# Run with default incident file (data/incident_data.json)
python -m src.main

# Run with a specific incident file
python -m src.main --file data/your_incident_data.json

# Run with a specific configuration file
python -m src.main --config config/your_config.yaml
```

### Setting Up Ollama for Local LLM Inference

#### Quick Setup

1. **Install Ollama**
   ```bash
   # Windows: Download from https://ollama.ai/download/windows
   # macOS: brew install ollama
   # Linux: curl -fsSL https://ollama.ai/install.sh | sh
   ```

2. **Start Service & Download Models**
   ```bash
   ollama serve
   ollama pull qwen2.5:14b    # Fast, 4GB RAM
   ollama pull qwen2.5:14b   # Better quality, 8GB RAM
   ```

#### Configuration

Update your config file to use Ollama:

```yaml
stages:
  cpe_extraction:
    llm_config:
      provider: "ollama"
      model_name: "qwen2.5:14b"
      temperature: 0
      max_tokens: 4096
      timeout: 60
      extra_params:
        format: "json"
        top_p: 0.9
```

#### Troubleshooting Ollama

- **Service not running**: Run `ollama serve`
- **Model not found**: Run `ollama pull model_name`
- **Out of memory**: Use smaller model (`qwen2.5:14b`)
- **Test setup**: `curl http://localhost:11434/api/generate -d '{"model": "qwen2.5:14b", "prompt": "Hello"}'`

#### Hybrid Setup (Recommended)

Use Ollama for bulk processing, cloud APIs for complex analysis:

```yaml
stages:
  cpe_extraction:
    llm_config:
      provider: "ollama"
      model_name: "qwen2.5:14b"
      
  incident_analysis:
    llm_config:
      provider: "openai"
      model_name: "gpt-4o"
```

### Command Line Options

- `--file, -f`: Path to the incidents file (default: `data/incident_data.json`)
- `--config, -c`: Path to the configuration file (default: `config/default_config.yaml`)

### Example

```bash
# Analyze incidents from a specific file
python -m src.main --file data/security_incidents.json --config config/production_config.yaml
```

## Architecture

The system processes incidents through multiple stages:

### Stage 1: Incident Parsing
- Parses JSON incident data
- Validates data structure
- Extracts assets, TTPs, and IOCs

### Stage 2: CPE Extraction
- Generates Common Platform Enumeration (CPE) strings
- Uses AI to identify software components
- Enhances incident data with structured identifiers

### Stage 3: Pre-processing
- Correlates incidents with vulnerability databases
- Performs automated CVE discovery
- Creates comprehensive vulnerability baseline

### Stage 4: Research
- Conducts advanced threat intelligence gathering
- Uses MCP tools for vulnerability research
- Gathers contextual information

### Stage 5: Analysis
- Performs risk assessment and prioritization
- Generates actionable recommendations
- Creates detailed analysis reports

### Stage 6: Report Generation
- Produces technical and customer-facing reports
- Formats findings in markdown
- Provides executive summaries

## Configuration

The application uses YAML configuration files located in the `config/` directory. Key configuration sections include:

- **LLM Settings**: Model selection and parameters
- **Stage Configuration**: Individual stage settings
- **MCP Server Settings**: Connection details for the vulnerability intelligence server
- **Token Management**: Budget and usage tracking
- **Validation Rules**: Data quality and validation settings

## Development

### VS Code Setup

The project includes VS Code launch configurations in `.vscode/launch.json`:

- **Python Debugger: Current File**: Debug the current Python file
- **RAD Security Pipeline**: Debug the main application with sample data

### Project Structure

```
rad-sec-analysis/
├── src/                          # Source code
│   ├── main.py                   # Main application entry point
│   ├── core/                     # Core functionality
│   ├── models/                   # Data models
│   ├── parsers/                  # Incident parsers
│   ├── stages/                   # Processing stages
│   ├── tools/                    # MCP and other tools
│   └── reports/                  # Report generators
├── config/                       # Configuration files
├── data/                         # Sample data files
├── docs/                         # Documentation
├── .vscode/                      # VS Code configuration
├── requirements.txt              # Python dependencies
├── .env.template                 # Environment template
└── README.md                     # This file
```

## Troubleshooting

### Common Issues

1. **MCP Server Not Running**
   ```
   Error: Failed to connect to MCP server
   ```
   **Solution**: Ensure the Vulnerability Intelligence MCP server is running on the expected port.

2. **Missing API Keys**
   ```
   Error: API key not found
   ```
   **Solution**: Verify that all required API keys are set in your `.env` file.

3. **Incident File Not Found**
   ```
   Error: Incidents file not found
   ```
   **Solution**: Check that the incident file path is correct and the file exists.

4. **Configuration File Issues**
   ```
   Error: Failed to load configuration
   ```
   **Solution**: Verify the YAML configuration file syntax and ensure all required sections are present.

### Logging

The application provides detailed logging output. To increase verbosity, modify the logging configuration in `src/main.py`:

```python
logging.basicConfig(
    level=logging.DEBUG,  # Change to DEBUG for more verbose output
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the logs for detailed error information
3. Ensure all prerequisites are properly configured
4. Email aronweiler@gmail.com

***© 2025 Aron Weiler. All rights reserved.***

*This software is provided for evaluation purposes only.
Commercial use, modification, or distribution is prohibited 
without explicit written permission from Aron Weiler.*