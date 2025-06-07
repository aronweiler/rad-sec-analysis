from enum import Enum
from typing import Dict, List, Literal, Optional, Any
from pydantic import BaseModel, Field

from .llm_config import LLMConfig

class Stage(str, Enum):
    """Stages in the analysis pipeline"""

    INCIDENT_PRE_PROCESSING = "incident_pre_processing"
    INITIAL_INCIDENT_AND_CVE_ANALYSIS = "initial_incident_and_cve_analysis"
    REPORT_GENERATION = "report_generation"


    # Other stages we could add
    # PRIORITIZED_RISK_AND_IMPACT_ASSESSMENT = "prioritized_risk_and_impact_assessment"
    # FINAL_INCIDENT_ANALYSIS = "final_incident_analysis"

class StageConfig(BaseModel):
    """Configuration for a specific stage"""

    stage: Stage = Field(..., description="Stage identifier")
    llm_config: Optional[LLMConfig] = Field(None, description="LLM configuration for this stage")
    enabled: bool = Field(True, description="Whether this stage is enabled")

    # Stage-specific settings
    max_context_length: Optional[int] = Field(
        None, description="Maximum context length for this stage"
    )

    strict_version_matching: Optional[bool] = Field(
        False, description="Enable strict version matching for tools"
    )

    # Token management
    token_budget: Optional[int] = Field(None, description="Token budget for this stage")
    enable_caching: Optional[bool] = Field(True, description="Enable response caching")
    cache_ttl: Optional[int] = Field(3600, description="Cache TTL in seconds")

    max_iterations: Optional[int] = Field(
        None, description="Maximum number of iterations for this stage"
    )

    # Tool and MCP server access control
    available_tools: Optional[List[str]] = Field(
        None, description="List of tool names available to this stage"
    )
    available_mcp_servers: Optional[List[str]] = Field(
        None, description="List of MCP server names available to this stage"
    )

    # NEW: Settings dictionary for custom stage-specific settings
    settings: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Custom settings dictionary for stage-specific configuration"
    )

    class Config:
        schema_extra = {
            "example": {
                "stage": "context_analysis",
                "llm_config": {
                    "provider": "openai",
                    "model_name": "gpt-4",
                    "temperature": 0.1,
                },
                "enabled": True,
                "strict_version_matching": True,
                "token_budget": 1000,
                "enable_caching": True,
                "max_iterations": 5,
                "available_tools": ["nvd_tool", "vulnerability_scanner"],
                "available_mcp_servers": ["vulnerability_intelligence"],
                "settings": {
                    "custom_threshold": 0.8,
                    "enable_feature_x": True,
                    "processing_mode": "advanced"
                }
            }
        }