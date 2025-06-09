from typing import Dict, List, Literal
from pydantic import BaseModel, Field


class MCPServerConfig(BaseModel):
    """Configuration for MCP servers"""

    name: str = Field(..., description="MCP server name")

    # Connection settings
    host: str = Field(..., description="MCP server host address")
    port: int = Field(..., ge=1, le=65535, description="MCP server port number")
    transport_type: Literal["stdio", "sse", "streamable_http"] = Field(
        "streamable_http", description="Transport type for MCP server connection"
    )

    # Commands to start the server if not running
    # This is typically used for local development or testing
    # These are optional as the server may already be running
    # Probably won't use these yet, since the MCP server I'm using is already running
    command: List[str] = Field(..., description="Commands to start the MCP server")

    enabled: bool = Field(True, description="Whether this MCP server is enabled")

    timeout: int = Field(30, description="Connection timeout")

    # Server-specific settings if required
    env_vars: Dict[str, str] = Field(
        default_factory=dict, description="Environment variables for the server"
    )

    class Config:
        schema_extra = {
            "example": {
                "name": "vulnerability_intelligence",
                "host": "localhost",
                "port": 8000,
                "command": ["python", "-m", "vulnerability_intelligence_mcp_server"],
                "enabled": True,
                "timeout": 30,
                "env_vars": {"CVE_API_KEY": "your-api-key"},
            }
        }
