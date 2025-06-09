from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator

from ..models.mcp_server_config import MCPServerConfig
from ..models.stage_config import Stage, StageConfig


class ApplicationConfig(BaseModel):
    """Main application configuration"""

    # Stage configurations
    stages: Dict[Stage, StageConfig] = Field(
        ..., description="Configuration for each stage"
    )

    # MCP server configurations
    mcp_servers: Dict[str, MCPServerConfig] = Field(
        default_factory=dict, description="MCP server configurations"
    )

    # Global settings
    debug: bool = Field(False, description="Enable debug mode")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        "INFO", description="Logging level"
    )

    # Incident parser settings
    incident_parser: str = Field("json_v1", description="Incident parser to use")

    # Token management
    global_token_budget: Optional[int] = Field(
        None, description="Global token budget per analysis"
    )
    enable_token_tracking: bool = Field(True, description="Enable token usage tracking")

    # Caching (only supportting memory for now, could extend in the future)
    cache_backend: Literal["memory", "redis", "file"] = Field(
        "memory", description="Cache backend type"
    )
    cache_config: Dict[str, Any] = Field(
        default_factory=dict, description="Cache-specific configuration"
    )

    @field_validator("stages")
    @classmethod
    def validate_required_stages(cls, v):
        """Ensure all required stages are configured"""
        required_stages = {
            Stage.INCIDENT_ANALYSIS,
            Stage.INCIDENT_PRE_PROCESSING,
        }

        configured_stages = set(v.keys())
        missing_stages = required_stages - configured_stages

        if missing_stages:
            raise ValueError(f"Missing required stages: {missing_stages}")

        return v

    def get_stage_config(self, stage: Stage) -> Optional[StageConfig]:
        """Get configuration for a specific stage"""
        return self.stages.get(stage)

    def get_enabled_stages(self) -> List[Stage]:
        """Get list of enabled stages"""
        return [stage for stage, config in self.stages.items() if config.enabled]

    def get_mcp_server_config(self, server_name: str) -> Optional[MCPServerConfig]:
        """Get configuration for a specific MCP server"""
        return self.mcp_servers.get(server_name)

    def get_enabled_mcp_servers(self) -> Dict[str, MCPServerConfig]:
        """Get enabled MCP servers"""
        return {
            name: config for name, config in self.mcp_servers.items() if config.enabled
        }

    class Config:
        schema_extra = {
            "example": {
                "stages": {
                    "analysis": {
                        "stage": "analysis",
                        "llm_config": {
                            "provider": "openai",
                            "model_name": "gpt-4",
                            "temperature": 0.1,
                        },
                        "enabled": True,
                    },
                    "cve_identification": {
                        "stage": "cve_identification",
                        "llm_config": {
                            "provider": "anthropic",
                            "model_name": "claude-3-sonnet-20240229",
                            "temperature": 0.0,
                        },
                        "enabled": True,
                    },
                },
                "mcp_servers": {
                    "vulnerability_intelligence": {
                        "name": "vulnerability_intelligence",
                        "host": "localhost",
                        "port": 8000,
                        "command": [],
                        "transport_type": "streamable_http",
                        "timeout": 30,
                        "env_vars": {},
                        "enabled": True,
                    }
                },
                "debug": False,
                "log_level": "INFO",
                "enable_token_tracking": True,
                "incident_parser": "json_v1",
            }
        }
