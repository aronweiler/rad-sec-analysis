from typing import Literal

MODEL_COSTS = {
    # Claude 4 Models
    "claude-opus-4-0": {
        "input": 0.015,
        "output": 0.075,
        "input_batch": 0.0075,
        "output_batch": 0.0375,
        "cache_write": 0.01875,
        "cache_read": 0.0015,
    },
    "claude-sonnet-4-0": {
        "input": 0.003,
        "output": 0.015,
        "input_batch": 0.0015,
        "output_batch": 0.0075,
        "cache_write": 0.00375,
        "cache_read": 0.0003,
    },
    # Anthropic Models (latest versions)
    "claude-3-opus-latest": {
        "input": 0.015,
        "output": 0.075,
        "input_batch": 0.0075,
        "output_batch": 0.0375,
    },
    "claude-3-5-haiku-latest": {
        "input": 0.0008,
        "output": 0.004,
        "input_batch": 0.0004,
        "output_batch": 0.002,
        "cache_write": 0.001,
        "cache_read": 0.00008,
    },
    "claude-3-5-sonnet-latest": {
        "input": 0.003,
        "output": 0.015,
        "input_batch": 0.0015,
        "output_batch": 0.0075,
        "cache_write": 0.00375,
        "cache_read": 0.0003,
    },
    "claude-3-7-sonnet-latest": {
        "input": 0.003,
        "output": 0.015,
        "input_batch": 0.0015,
        "output_batch": 0.0075,
        "cache_write": 0.00375,
        "cache_read": 0.0003,
    },
    # Claude 3.7 Models (same pricing as Claude 3.5 Sonnet)
    "us.anthropic.claude-3-7-sonnet-20250219-v1:0": {
        "input": 0.003,
        "output": 0.015,
        "input_batch": 0.0015,
        "output_batch": 0.0075,
        "cache_write": 0.00375,
        "cache_read": 0.0003,
    },
    # Claude 3.5 Models
    "us.anthropic.claude-3-5-sonnet-20241022-v2:0": {
        "input": 0.003,
        "output": 0.015,
        "input_batch": 0.0015,
        "output_batch": 0.0075,
        "cache_write": 0.00375,
        "cache_read": 0.0003,
    },
    "us.anthropic.claude-3-5-haiku-20241022-v1:0": {
        "input": 0.0008,
        "output": 0.004,
        "input_batch": 0.0004,
        "output_batch": 0.002,
        "cache_write": 0.001,
        "cache_read": 0.00008,
    },
    # Claude 3 Models
    "us.anthropic.claude-3-opus-20240229-v1:0": {
        "input": 0.015,
        "output": 0.075,
        "input_batch": 0.0075,
        "output_batch": 0.0375,
    },
    "anthropic.claude-3-haiku-20240307-v1:0": {
        "input": 0.00025,
        "output": 0.00125,
        "input_batch": 0.000125,
        "output_batch": 0.000625,
    },
    "anthropic.claude-3-5-sonnet-20240620-v1:0": {
        "input": 0.003,
        "output": 0.015,
        "input_batch": 0.0015,
        "output_batch": 0.0075,
    },
    # Claude 2.x Models
    "anthropic.claude-2.1": {
        "input": 0.008,
        "output": 0.024,
    },
    "anthropic.claude-2.0": {
        "input": 0.008,
        "output": 0.024,
    },
    "anthropic.claude-instant-1": {
        "input": 0.0008,
        "output": 0.0024,
    },
    # OpenAI Models
    "gpt-4.1": {
        "input": 0.0000025,
        "output": 0.00001,
    },
    "gpt-4o": {
        "input": 0.0000025,
        "output": 0.00001,
    },
    "o4-mini": {
        "input": 0.000003,
        "output": 0.000012,
    },
    "o3": {
        "input": 0.000015,
        "output": 0.00006,
    },
    "o1-mini": {
        "input": 0.000003,
        "output": 0.000012,
    },
    "o1-preview": {
        "input": 0.000015,
        "output": 0.00006,
    },
    "azure-gpt-4o": {
        "input": 0.0000025,
        "output": 0.00001,
    },
    # Local Models
    "lmstudio-community/meta-llama-3.1-8b-instruct": {
        "input": 0,
        "output": 0,
    },
    "TheBloke/deepseek-coder-33B-instruct-GGUF": {
        "input": 0,
        "output": 0,
    },
}


def get_token_cost(
    token_count: int,
    model_name: str,
    token_type: Literal[
        "input", "output", "input_batch", "output_batch", "cache_write", "cache_read"
    ],
):
    # All costs are per 1000 tokens
    if token_type not in MODEL_COSTS[model_name]:
        raise ValueError(
            f"Token type '{token_type}' not supported for model '{model_name}'"
        )
    return MODEL_COSTS[model_name][token_type] * (token_count / 1000)
