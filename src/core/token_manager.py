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

from src.models.llm_config import LLMProvider
from src.models.stage_config import Stage

from ..models.model_costs import MODEL_COSTS, get_token_cost

logger = logging.getLogger(__name__)


@dataclass
class TokenUsage:
    """Token usage tracking for a single operation"""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_estimate: float = 0.0
    timestamp: float = field(default_factory=time.time)

    @property
    def efficiency_ratio(self) -> float:
        """Calculate output/input token ratio"""
        if self.input_tokens == 0:
            return 0.0
        return self.output_tokens / self.input_tokens


@dataclass
class StageBudget:
    """Token budget for a reasoning stage"""

    allocated: int
    used: int = 0
    remaining: int = 0

    def __post_init__(self):
        self.remaining = self.allocated - self.used

    def consume(self, tokens: int) -> bool:
        """Consume tokens from budget. Returns True if successful."""
        if tokens > self.remaining:
            return False

        self.used += tokens
        self.remaining = self.allocated - self.used
        return True

    @property
    def utilization_percent(self) -> float:
        """Calculate budget utilization percentage"""
        if self.allocated == 0:
            return 0.0
        return (self.used / self.allocated) * 100


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


class ContextOptimizer:
    """Optimizes context to fit within token limits"""

    def __init__(self, token_counter: TokenCounter):
        self.token_counter = token_counter

    def optimize_context(
        self,
        context_data: Dict[str, Any],
        max_tokens: int,
        model: str = "default",
        priority_fields: Optional[List[str]] = None,
    ) -> Tuple[Dict[str, Any], int]:
        """
        Optimize context data to fit within token limits.

        Returns:
            Tuple of (optimized_context, estimated_tokens)
        """
        if not priority_fields:
            priority_fields = ["incident_id", "title", "description", "affected_assets"]

        optimized = {}
        current_tokens = 0

        # First pass: Add priority fields
        for field in priority_fields:
            if field in context_data:
                field_text = self._serialize_field(context_data[field])
                field_tokens = self.token_counter.count_tokens(field_text, model)

                if current_tokens + field_tokens <= max_tokens:
                    optimized[field] = context_data[field]
                    current_tokens += field_tokens
                else:
                    # Truncate field if it's too large
                    truncated = self._truncate_field(
                        context_data[field], max_tokens - current_tokens, model
                    )
                    if truncated:
                        optimized[field] = truncated
                        current_tokens += self.token_counter.count_tokens(
                            self._serialize_field(truncated), model
                        )
                    break

        # Second pass: Add remaining fields if space allows
        remaining_tokens = max_tokens - current_tokens
        for field, value in context_data.items():
            if field not in optimized and remaining_tokens > 50:  # Reserve some tokens
                field_text = self._serialize_field(value)
                field_tokens = self.token_counter.count_tokens(field_text, model)

                if field_tokens <= remaining_tokens:
                    optimized[field] = value
                    current_tokens += field_tokens
                    remaining_tokens -= field_tokens

        return optimized, current_tokens

    def _serialize_field(self, value: Any) -> str:
        """Convert field value to string for token counting"""
        if isinstance(value, str):
            return value
        elif isinstance(value, (list, dict)):
            return str(value)  # Could be improved with better serialization
        else:
            return str(value)

    def _truncate_field(self, value: Any, max_tokens: int, model: str) -> Any:
        """Truncate a field to fit within token limit"""
        if isinstance(value, str):
            return self._truncate_text(value, max_tokens, model)
        elif isinstance(value, list):
            return self._truncate_list(value, max_tokens, model)
        elif isinstance(value, dict):
            return self._truncate_dict(value, max_tokens, model)
        else:
            return value

    def _truncate_text(self, text: str, max_tokens: int, model: str) -> str:
        """
        Truncates the input text so that its token count does not exceed the specified maximum for a given model.
        Uses a binary search to efficiently find the largest prefix of the text (by word) that fits within the token limit.
        If truncation is necessary, appends an ellipsis ("...") to the result.
        Args:
            text (str): The input text to be truncated.
            max_tokens (int): The maximum allowed number of tokens.
            model (str): The model name used for token counting.
        Returns:
            str: The truncated text, possibly ending with an ellipsis if truncation occurred.
        """
        if self.token_counter.count_tokens(text, model) <= max_tokens:
            return text

        # Binary search for optimal truncation point
        words = text.split()
        left, right = 0, len(words)

        while left < right:
            mid = (left + right + 1) // 2
            truncated = " ".join(words[:mid]) + "..."

            if self.token_counter.count_tokens(truncated, model) <= max_tokens:
                left = mid
            else:
                right = mid - 1

        if left == 0:
            return "..."

        return " ".join(words[:left]) + "..."

    def _truncate_list(
        self, items: List[Any], max_tokens: int, model: str
    ) -> List[Any]:
        """Truncate list to fit within token limit"""
        truncated = []
        current_tokens = 0

        for item in items:
            item_text = self._serialize_field(item)
            item_tokens = self.token_counter.count_tokens(item_text, model)

            if current_tokens + item_tokens <= max_tokens:
                truncated.append(item)
                current_tokens += item_tokens
            else:
                break

        return truncated

    def _truncate_dict(
        self, data: Dict[str, Any], max_tokens: int, model: str
    ) -> Dict[str, Any]:
        """Truncate dictionary to fit within token limit"""
        truncated = {}
        current_tokens = 0

        # Prioritize certain keys
        priority_keys = ["id", "name", "title", "description", "type"]

        # Add priority keys first
        for key in priority_keys:
            if key in data:
                value_text = self._serialize_field(data[key])
                value_tokens = self.token_counter.count_tokens(value_text, model)

                if current_tokens + value_tokens <= max_tokens:
                    truncated[key] = data[key]
                    current_tokens += value_tokens

        # Add remaining keys
        for key, value in data.items():
            if key not in truncated:
                value_text = self._serialize_field(value)
                value_tokens = self.token_counter.count_tokens(value_text, model)

                if current_tokens + value_tokens <= max_tokens:
                    truncated[key] = value
                    current_tokens += value_tokens
                else:
                    break

        return truncated


class TokenManager:
    """Main token management system"""

    def __init__(self, global_budget: Optional[int] = None):
        self.global_budget = global_budget
        self.global_used = 0
        self.stage_budgets: Dict[Stage, StageBudget] = {}
        self.usage_history: List[TokenUsage] = []
        self.stage_usage: Dict[Stage, List[TokenUsage]] = defaultdict(list)

        self.token_counter = TokenCounter()
        self.context_optimizer = ContextOptimizer(self.token_counter)

        # Model costs are now loaded from model_costs.py
        self.model_costs = MODEL_COSTS

    def set_stage_budget(self, stage: Stage, budget: int):
        """Set token budget for a reasoning stage"""
        self.stage_budgets[stage] = StageBudget(allocated=budget)
        logger.debug(f"Set budget for {stage}: {budget} tokens")

    def can_consume_tokens(self, stage: Stage, tokens: int) -> bool:
        """Check if tokens can be consumed from stage budget"""
        # Check global budget
        if self.global_budget and (self.global_used + tokens) > self.global_budget:
            return False

        # Check stage budget
        stage_budget = self.stage_budgets.get(stage)
        if stage_budget and not stage_budget.consume(tokens):
            return False

        return True

    def consume_tokens(
        self,
        stage: Stage,
        input_tokens: int,
        output_tokens: int,
        provider: LLMProvider,
        model: str,
    ) -> TokenUsage:
        """Record token consumption"""
        total_tokens = input_tokens + output_tokens

        # Update global usage
        self.global_used += total_tokens

        # Update stage budget
        stage_budget = self.stage_budgets.get(stage)
        if stage_budget:
            stage_budget.consume(total_tokens)

        # Calculate cost estimate
        cost = self._estimate_cost(provider, model, input_tokens, output_tokens)

        # Create usage record
        usage = TokenUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            cost_estimate=cost,
        )

        # Store usage
        self.usage_history.append(usage)
        self.stage_usage[stage].append(usage)

        logger.debug(
            f"Consumed {total_tokens} tokens for {stage} "
            f"(input: {input_tokens}, output: {output_tokens}, cost: ${cost:.4f})"        )
        return usage

    def _estimate_cost(
        self, provider: LLMProvider, model: str, input_tokens: int, output_tokens: int
    ) -> float:
        """Estimate cost for token usage using model_costs.py"""
        try:
            # Try to get cost directly using the model name
            if model in self.model_costs:
                input_cost = get_token_cost(input_tokens, model, "input")
                output_cost = get_token_cost(output_tokens, model, "output")
                return input_cost + output_cost
            
            # If model not found, use default rates
            logger.warning(f"Model '{model}' not found in cost data, using default rates")
            default_input_rate = 0.001  # $0.001 per 1K tokens
            default_output_rate = 0.002  # $0.002 per 1K tokens
            return (input_tokens / 1000) * default_input_rate + (output_tokens / 1000) * default_output_rate

        except Exception as e:
            logger.error(f"Error calculating cost for model '{model}': {e}")            # Fallback to default rates on error
            default_input_rate = 0.001
            default_output_rate = 0.002
            return (input_tokens / 1000) * default_input_rate + (output_tokens / 1000) * default_output_rate

    def get_stage_summary(self, stage: Stage) -> Dict[str, Any]:
        """Get token usage summary for a stage"""
        stage_usage = self.stage_usage.get(stage, [])
        stage_budget = self.stage_budgets.get(stage)

        if not stage_usage:
            return {
                "stage": stage,
                "total_tokens": 0,
                "total_cost": 0.0,
                "operations": 0,
                "budget_allocated": stage_budget.allocated if stage_budget else None,
                "budget_used": 0,
                "budget_remaining": stage_budget.remaining if stage_budget else None,
            }

        total_tokens = sum(usage.total_tokens for usage in stage_usage)
        total_cost = sum(usage.cost_estimate for usage in stage_usage)

        return {
            "stage": stage,
            "total_tokens": total_tokens,
            "total_cost": total_cost,
            "operations": len(stage_usage),
            "average_tokens_per_operation": total_tokens / len(stage_usage),
            "budget_allocated": stage_budget.allocated if stage_budget else None,
            "budget_used": stage_budget.used if stage_budget else total_tokens,
            "budget_remaining": stage_budget.remaining if stage_budget else None,
            "budget_utilization": (
                stage_budget.utilization_percent if stage_budget else None
            ),
        }

    def get_global_summary(self) -> Dict[str, Any]:
        """Get global token usage summary"""
        total_cost = sum(usage.cost_estimate for usage in self.usage_history)

        return {
            "total_tokens": self.global_used,
            "total_cost": total_cost,
            "total_operations": len(self.usage_history),
            "global_budget": self.global_budget,
            "global_remaining": (
                (self.global_budget - self.global_used) if self.global_budget else None
            ),
            "average_tokens_per_operation": (
                self.global_used / len(self.usage_history) if self.usage_history else 0
            ),
            "stages_active": len(self.stage_usage),
        }

    def optimize_context_for_stage(
        self,
        context_data: Dict[str, Any],
        stage: Stage,
        model: str = "default",
    ) -> Tuple[Dict[str, Any], int]:
        """Optimize context data for a specific stage"""
        stage_budget = self.stage_budgets.get(stage)

        # Reserve some tokens for output
        if stage_budget:
            max_input_tokens = int(
                stage_budget.remaining * 0.7
            )  # 70% for input, 30% for output
        else:
            max_input_tokens = 2000  # Default limit

        return self.context_optimizer.optimize_context(
            context_data, max_input_tokens, model
        )

    def reset_budgets(self):
        """Reset all token budgets and usage"""
        self.global_used = 0
        self.stage_budgets.clear()
        self.usage_history.clear()
        self.stage_usage.clear()
        logger.info("Token budgets and usage reset")
