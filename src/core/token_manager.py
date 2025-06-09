"""
Token Management System

Handles token counting, budget tracking, and context optimization for LLM interactions.
"""

import logging
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import tiktoken
from pydantic import BaseModel

from ..models.llm_config import LLMProvider
from ..models.stage_config import Stage

from ..models.model_costs import MODEL_COSTS, get_token_cost

logger = logging.getLogger(__name__)


class TokenCounter:
    """Utility for counting tokens in text"""

    def __init__(self):
        self.encoders: Dict[str, tiktoken.Encoding] = {}
        self._load_encoders()

    def _load_encoders(self):
        """Load tiktoken encoders for different models"""
        try:
            # Common encoders
            self.encoders["gpt-4"] = tiktoken.encoding_for_model("gpt-4")
            self.encoders["gpt-3.5-turbo"] = tiktoken.encoding_for_model(
                "gpt-3.5-turbo"
            )
            self.encoders["text-davinci-003"] = tiktoken.encoding_for_model(
                "text-davinci-003"
            )

            # Default encoder for unknown models
            self.encoders["default"] = tiktoken.get_encoding("cl100k_base")

        except Exception as e:
            logger.warning(f"Failed to load some tiktoken encoders: {e}")
            # Fallback to default encoder            self.encoders["default"] = tiktoken.get_encoding("cl100k_base")

    def count_tokens(self, text: str, model: str = "default") -> int:
        """Count tokens in text for a specific model"""
        if not text:
            return 0

        # Map model names to encoder keys
        encoder_key = self._get_encoder_key(model)
        encoder = self.encoders.get(encoder_key, self.encoders["default"])

        try:
            return len(encoder.encode(text))
        except Exception as e:
            logger.warning(f"Token counting failed for model {model}: {e}")
            # Fallback to rough estimation
            return int(len(text.split()) * 1.3)  # Rough approximation

    def _get_encoder_key(self, model: str) -> str:
        """Map model name to encoder key"""
        model_lower = model.lower()

        if "gpt-4" in model_lower:
            return "gpt-4"
        elif "gpt-3.5" in model_lower or "turbo" in model_lower:
            return "gpt-3.5-turbo"
        elif "davinci" in model_lower:
            return "text-davinci-003"
        else:
            return "default"

    def estimate_tokens_for_messages(
        self, messages: List[Dict[str, str]], model: str = "default"
    ) -> int:
        """Estimate tokens for a list of chat messages"""
        total_tokens = 0

        for message in messages:
            # Add tokens for message content
            content = message.get("content", "")
            total_tokens += self.count_tokens(content, model)

            # Add overhead tokens for message structure
            total_tokens += 4  # Rough estimate for message overhead

        # Add overhead for the conversation structure
        total_tokens += 3

        return total_tokens
