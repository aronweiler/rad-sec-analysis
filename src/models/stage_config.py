from enum import Enum
from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from .llm_config import LLMConfig

class Stage(str, Enum):
    """Stages in the analysis pipeline"""

    INITIAL_INCIDENT_AND_CVE_ANALYSIS = "initial_incident_and_cve_analysis"
    PRIORITIZED_RISK_AND_IMPACT_ASSESSMENT = "prioritized_risk_and_impact_assessment"
    FINAL_INCIDENT_ANALYSIS = "final_incident_analysis"

class StageConfig(BaseModel):
    """Configuration for a specific stage"""

    stage: Stage = Field(..., description="Stage identifier")
    llm_config: LLMConfig = Field(..., description="LLM configuration for this stage")
    enabled: bool = Field(True, description="Whether this stage is enabled")

    # Stage-specific settings
    max_context_length: Optional[int] = Field(
        None, description="Maximum context length for this stage"
    )

    # Token management
    token_budget: Optional[int] = Field(None, description="Token budget for this stage")
    enable_caching: bool = Field(True, description="Enable response caching")
    cache_ttl: int = Field(3600, description="Cache TTL in seconds")
    
    max_iterations: Optional[int] = Field(
        None, description="Maximum number of iterations for this stage"
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
                "system_message": "You are a cybersecurity analyst specializing in incident context analysis.",
                "token_budget": 1000,
                "enable_caching": True,
                "max_iterations": 5,
            }
        }