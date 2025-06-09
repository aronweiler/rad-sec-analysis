# MCP Integration Guide

This guide explains how to integrate the RAD Security Analysis Agent with the vulnerability intelligence MCP server.

https://github.com/firetix/vulnerability-intelligence-mcp-server

## Prerequisites

Clone the repository to `<repository directory>\vulnerability-intelligence-mcp-server`

## Integration Options

### Option 1: Git Submodule (Recommended)

Add your MCP server as a git submodule to keep them in sync:

```bash
cd <repository directory>\rad-sec-analysis
git submodule add ../vulnerability-intelligence-mcp-server mcp-servers/vulnerability-intelligence
git submodule update --init --recursive
```

### Option 2: Docker Compose Integration

Create a unified docker-compose.yml that runs both services:

```yaml
version: '3.8'

services:
  vulnerability-mcp-server:
    build: ./mcp-servers/vulnerability-intelligence
    ports:
      - "8000:8000"
    environment:
      - MCP_SERVER_PORT=8000
      - MCP_SERVER_HOST=0.0.0.0
      - DEBUG=false
    restart: unless-stopped
    
  rad-analysis-agent:
    build: .
    depends_on:
      - vulnerability-mcp-server
    environment:
      - MCP_SERVER_URL=http://vulnerability-mcp-server:8000
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./data:/app/data
      - ./configs:/app/configs
```

### Option 3: Monorepo Structure

Reorganize into a single repository:

```
rad-sec-analysis/
├── src/
│   ├── agent/          # Main analysis agent
│   ├── mcp-server/     # Vulnerability intelligence server
│   ├── models/         # Shared data models
│   └── core/           # Shared infrastructure
├── tests/
├── configs/
└── docker-compose.yml
```

## Current MCP Client Implementation

The MCP client framework we just built includes:

### MCPClient Class
- Connects to your vulnerability intelligence server
- Supports all your available tools:
  - `cve_lookup` - CVE details from NVD
  - `package_vulnerability_check` - Python package vulnerabilities
  - `get_epss_score` - EPSS exploitation scores
  - `search_vulnerabilities` - Advanced vulnerability search
  - `get_exploit_availability` - Public exploit detection
  - `get_vulnerability_timeline` - Timeline and patch status

### MCPClientManager
- Manages multiple MCP servers
- Handles connection lifecycle
- Provides unified tool calling interface

## Configuration

The system uses your existing MCP server configuration:

```yaml
mcp_servers:
  vulnerability_intelligence:
    name: "vulnerability_intelligence"
    command: ["python", "-m", "mcp_simple_tool.server"]
    enabled: true
    timeout: 30
    env_vars:
      MCP_USER_AGENT: "RAD Security Analysis Agent v1.0"
```

## Testing the Integration

Run the test script to verify everything works:

```bash
cd <repository directory>\rad-sec-analysis
python test_mcp_integration.py
```

This will:
1. Load the default configuration
2. Initialize the MCP client manager
3. Connect to your vulnerability intelligence server
4. Test all available tools
5. Verify token management and caching

## Next Steps

1. **Start your MCP server**:
   ```bash
   cd <repository directory>\vulnerability-intelligence-mcp-server
   docker-compose up -d
   ```

2. **Test the integration**:
   ```bash
   cd <repository directory>\rad-sec-analysis
   python test_mcp_integration.py
   ```

3. **Choose integration approach**:
   - Git submodule for development
   - Docker compose for deployment
   - Monorepo for long-term maintenance

4. **Build the processing pipeline**:
   - Incident Parser (next component)
   - Context Analyzer (first AI component)
   - CVE Identifier (AI + MCP integration)

## Production Considerations

### Real MCP Integration
The current implementation uses simulated tool calls. For production:

1. **Use MCP Python SDK** when available
2. **Implement proper MCP protocol** communication
3. **Add connection pooling** for multiple concurrent requests
4. **Implement retry logic** with exponential backoff

### Security
- Secure API key management
- Network security between services
- Input validation for tool parameters
- Rate limiting and abuse prevention

### Monitoring
- Tool call success/failure rates
- Response times and performance
- Token usage and costs
- Error tracking and alerting

## Tool Usage Examples

### CVE Lookup
```python
result = await mcp_manager.call_tool(
    "vulnerability_intelligence",
    "cve_lookup", 
    {"cve_id": "CVE-2021-44228"}
)
```

### Package Vulnerability Check
```python
result = await mcp_manager.call_tool(
    "vulnerability_intelligence",
    "package_vulnerability_check",
    {"package_name": "requests", "version": "2.25.1"}
)
```

### EPSS Score Lookup
```python
result = await mcp_manager.call_tool(
    "vulnerability_intelligence",
    "get_epss_score",
    {"cve_id": "CVE-2021-44228"}
)
```

This integration provides a solid foundation for the vulnerability analysis pipeline while leveraging your existing, well-structured MCP server.