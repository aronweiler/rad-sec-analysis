# External Dependencies

## Vulnerability Intelligence MCP Server

**Repository**: https://github.com/firetix/vulnerability-intelligence-mcp-server  
**Maintainer**: firetix  
**Purpose**: Provides comprehensive vulnerability intelligence tools via MCP protocol

### Integration Strategy

#### Option 1: Git Submodule (Recommended)

```bash
# Add as submodule
git submodule add https://github.com/firetix/vulnerability-intelligence-mcp-server.git external/vulnerability-intelligence-mcp-server

# Initialize and update
git submodule update --init --recursive

# To update to latest version
cd external/vulnerability-intelligence-mcp-server
git pull origin main
cd ../..
git add external/vulnerability-intelligence-mcp-server
git commit -m "Update vulnerability intelligence MCP server"
```

#### Option 2: Docker Compose Integration

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  vulnerability-mcp-server:
    build: 
      context: https://github.com/firetix/vulnerability-intelligence-mcp-server.git
      dockerfile: Dockerfile
    ports:
      - "${MCP_SERVER_PORT:-8000}:8000"
    environment:
      - MCP_SERVER_PORT=${MCP_SERVER_PORT:-8000}
      - MCP_SERVER_HOST=${MCP_SERVER_HOST:-0.0.0.0}
      - DEBUG=${DEBUG:-false}
      - MCP_USER_AGENT=RAD Security Analysis Agent v1.0
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    
  rad-analysis-agent:
    build: .
    depends_on:
      vulnerability-mcp-server:
        condition: service_healthy
    environment:
      - MCP_SERVER_URL=http://vulnerability-mcp-server:8000
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    volumes:
      - ./data:/app/data
      - ./configs:/app/configs
      - ./output:/app/output
    ports:
      - "8080:8080"
```

#### Option 3: Local Development Setup

For development, clone separately and run locally:

```bash
# Clone the MCP server separately
git clone https://github.com/firetix/vulnerability-intelligence-mcp-server.git ../vulnerability-intelligence-mcp-server

# Start the server
cd ../vulnerability-intelligence-mcp-server
docker-compose up -d

# Return to your project
cd ../rad-sec-analysis
python test_mcp_integration.py
```

### Available Tools

The external MCP server provides these tools:

1. **cve_lookup** - CVE vulnerability lookup from NVD
2. **package_vulnerability_check** - Python package vulnerability checking
3. **get_epss_score** - EPSS exploitation probability scores
4. **calculate_cvss_score** - CVSS score calculation
5. **search_vulnerabilities** - Advanced vulnerability search
6. **get_exploit_availability** - Public exploit detection
7. **get_vulnerability_timeline** - Timeline and patch status
8. **get_vex_status** - VEX status checking

### Configuration

Update your `configs/config.yaml`:

```yaml
mcp_servers:
  vulnerability_intelligence:
    name: "vulnerability_intelligence"
    # For local development
    command: ["python", "-m", "mcp_simple_tool.server"]
    # For Docker
    # base_url: "http://localhost:8000"
    enabled: true
    timeout: 30
    env_vars:
      MCP_USER_AGENT: "RAD Security Analysis Agent v1.0"
```

### Version Management

#### Pinning Versions
For production stability, pin to specific commits:

```bash
cd external/vulnerability-intelligence-mcp-server
git checkout v1.2.3  # or specific commit hash
cd ../..
git add external/vulnerability-intelligence-mcp-server
git commit -m "Pin MCP server to v1.2.3"
```

#### Updating Dependencies
Regular update process:

```bash
# Check for updates
cd external/vulnerability-intelligence-mcp-server
git fetch origin
git log HEAD..origin/main --oneline

# Update if desired
git pull origin main
cd ../..
git add external/vulnerability-intelligence-mcp-server
git commit -m "Update MCP server to latest"
```

### Contribution Strategy

Since this is an external dependency:

1. **Report Issues**: Use their GitHub issues for bugs/feature requests
2. **Contribute Back**: Submit PRs to improve the MCP server
3. **Fork if Needed**: Create your own fork for custom modifications
4. **Stay Updated**: Monitor releases and security updates

### Fallback Strategy

In case the external server is unavailable:

1. **Mock Implementation**: Use our simulated responses
2. **Alternative Sources**: Integrate other vulnerability databases
3. **Cached Responses**: Rely on cached data for known CVEs
4. **Graceful Degradation**: Continue analysis with reduced functionality

### Testing with External Dependency

```bash
# Test external server availability
curl -f http://localhost:8000/health

# Test MCP integration
python test_mcp_integration.py

# Test with real CVE data
python -c "
import asyncio
from src.core.mcp_client import MCPClientManager
from src.core.config_loader import load_config

async def test():
    config = load_config()
    async with MCPClientManager().managed_session(config.get_enabled_mcp_servers()) as manager:
        result = await manager.call_tool('vulnerability_intelligence', 'cve_lookup', {'cve_id': 'CVE-2021-44228'})
        print(result)

asyncio.run(test())
"
```

This approach keeps your project independent while leveraging the excellent vulnerability intelligence capabilities of the external MCP server.