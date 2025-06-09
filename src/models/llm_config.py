from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class LLMProvider(str, Enum):
    """Supported LLM providers"""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    GOOGLE = "google"
    OLLAMA = "ollama"
    HUGGINGFACE = "huggingface"


class LLMConfig(BaseModel):
    """Configuration for a specific LLM"""

    provider: LLMProvider = Field(..., description="LLM provider")
    model_name: str = Field(..., description="Model name/identifier")
    api_key: Optional[str] = Field(None, description="API key (can be set via env var)")
    api_base: Optional[str] = Field(None, description="Custom API base URL")
    temperature: float = Field(0.1, ge=0.0, le=2.0, description="Model temperature")
    max_tokens: Optional[int] = Field(
        None, gt=0, description="Maximum tokens per request"
    )
    timeout: int = Field(30, gt=0, description="Request timeout in seconds")
    max_retries: int = Field(3, ge=0, description="Maximum retry attempts")

    # Provider-specific settings
    extra_params: Dict[str, Any] = Field(
        default_factory=dict, description="Additional provider-specific parameters"
    )

    @field_validator("temperature")
    @classmethod
    def validate_temperature(cls, v):
        """Validate temperature is in reasonable range"""
        if not 0.0 <= v <= 2.0:
            raise ValueError("Temperature must be between 0.0 and 2.0")
        return v

    class Config:
        schema_extra = {
            "example": {
                "provider": "openai",
                "model_name": "gpt-4",
                "temperature": 0.1,
                "max_tokens": 2000,
                "timeout": 30,
                "max_retries": 3,
                "extra_params": {"top_p": 0.9, "frequency_penalty": 0.0},
            }
        }
