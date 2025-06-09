from enum import Enum
from typing import Dict, List, Literal, Optional, Any
from pydantic import BaseModel, Field

from .llm_config import LLMConfig


class Stage(str, Enum):
    """Stages in the analysis pipeline"""

    INCIDENT_PRE_PROCESSING = "incident_pre_processing"
    CPE_EXTRACTION = "cpe_extraction"
    INCIDENT_RESEARCH = "incident_research"
    INCIDENT_ANALYSIS = "incident_analysis"
    REPORT_GENERATION = "report_generation"

    # Other stages we could add
    # PRIORITIZED_RISK_AND_IMPACT_ASSESSMENT = "prioritized_risk_and_impact_assessment"
    # FINAL_INCIDENT_ANALYSIS = "final_incident_analysis"


class CompressionStrategy(str, Enum):
    """Compression strategies available"""

    INTELLIGENT_WITH_TOOL = "intelligent_with_tool"
    INTELLIGENT_PROMPT = "intelligent_prompt"
    SIMPLE_TRUNCATION = "simple_truncation"


class CompressionConfig(BaseModel):
    """Configuration for context compression"""

    enabled: bool = Field(True, description="Whether compression is enabled")

    # Trigger settings
    token_threshold: int = Field(
        4000, description="Token count threshold to trigger compression"
    )

    # Compression LLM
    compression_llm_config: Optional[LLMConfig] = Field(
        None, description="LLM config for compression (uses stage LLM if not specified)"
    )

    # Tool-based compression
    compression_tool: Optional[str] = Field(
        None, description="Name of tool to use for compression"
    )

    # Fallback settings
    fallback_strategy: CompressionStrategy = Field(
        CompressionStrategy.SIMPLE_TRUNCATION,
        description="Fallback strategy when primary compression fails",
    )

    preserve_last_n_messages: int = Field(
        3, description="Number of recent messages to preserve in fallback"
    )

    # Compression behavior
    preserve_system_messages: bool = Field(
        True, description="Always preserve system messages"
    )

    max_compression_retries: int = Field(
        2, description="Maximum retries for tool-based compression validation errors"
    )

    # Compression prompt settings
    compression_prompt_path: Optional[str] = Field(
        "prompts/compression_system_prompt.txt",
        description="Path to compression prompt file",
    )


class StageConfig(BaseModel):
    """Configuration for a specific stage"""

    stage: Stage = Field(..., description="Stage identifier")
    llm_config: Optional[LLMConfig] = Field(
        None, description="LLM configuration for this stage"
    )
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

    max_final_retries: Optional[int] = Field(
        3, description="Maximum number of retries for final output generation"
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
        description="Custom settings dictionary for stage-specific configuration",
    )

    compression_config: Optional[CompressionConfig] = Field(
        None, description="Context compression configuration"
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
                    "processing_mode": "advanced",
                },
            }
        }
