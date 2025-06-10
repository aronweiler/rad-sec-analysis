import asyncio
import logging
from typing import Any, Dict, List, Optional, Union
from langchain_core.messages import BaseMessage

from ..core.token_manager import TokenCounter

logger = logging.getLogger(__name__)
token_counter = TokenCounter()


async def llm_invoke_with_retry(
    llm_with_tools,
    messages: Union[List[BaseMessage], List[Dict[str, Any]]],
    config: Optional[Dict[str, Any]] = None,
    max_retries: int = 5,
    initial_wait: float = 5,
    backoff_multiplier: float = 1.5,
    rate_limit_wait: float = 90.0,  # Longer wait for rate limits
    **kwargs,
) -> Any:
    """
    Wrapper function for LangChain LLM ainvoke with exponential backoff retry logic.

    Args:
        llm_with_tools: The LangChain LLM instance with tools
        messages: List of messages to send to the LLM
        config: Optional configuration dict for the LLM call
        max_retries: Maximum number of retry attempts (default: 5)
        initial_wait: Initial wait time in seconds before first retry (default: 15.0)
        backoff_multiplier: Multiplier for exponential backoff (default: 2.0)
        **kwargs: Additional keyword arguments to pass to ainvoke

    Returns:
        The response from the LLM

    Raises:
        Exception: The last exception encountered if all retries are exhausted
    """
    last_exception = None

    for attempt in range(max_retries + 1):  # +1 because we include the initial attempt
        try:
            # Prepare arguments for ainvoke
            invoke_args = [messages]
            invoke_kwargs = kwargs.copy()

            # Convert messages to dicts
            message_dicts = [msg.model_dump(mode="json") for msg in messages]

            logger.info(
                f"LLM call attempt {attempt + 1} with {len(messages)} messages estimated at {token_counter.estimate_tokens_for_messages(message_dicts)} tokens"
            )

            if config is not None:
                invoke_kwargs["config"] = config

            # Make the LLM call
            response = await llm_with_tools.ainvoke(*invoke_args, **invoke_kwargs)
            return response

        except Exception as e:
            last_exception = e

            # Check if this is a rate limit error
            is_rate_limit = (
                "rate limit" in str(e).lower()
                or "429" in str(e)
                or "too many requests" in str(e).lower()
            )

            if is_rate_limit:
                wait_time = rate_limit_wait
                logging.warning(f"Rate limit detected. Waiting {wait_time} seconds...")
            else:
                wait_time = initial_wait * (backoff_multiplier**attempt)
                
            # Fix the inevitable issue with no tool calls but has tool calls
            is_no_response_message = (
                "did not have response" in str(e).lower()
                or "The following tool_call_ids" in str(e)
            )
            if is_no_response_message:
                # Strip off the last AIMessage if it exists
                if messages and isinstance(messages[-1], BaseMessage) and messages[-1].type == "ai":
                    logging.warning(
                        "No response message detected, removing last AIMessage from messages."
                    )
                    messages.pop()

            # If this was the last attempt, don't wait and re-raise
            if attempt == max_retries:
                logging.error(
                    f"LLM call failed after {max_retries} retries. Last error: {str(e)}"
                )
                raise e

            # Calculate wait time with exponential backoff
            wait_time = initial_wait * (backoff_multiplier**attempt)

            logging.warning(
                f"LLM call attempt {attempt + 1} failed: {str(e)}. "
                f"Retrying in {wait_time:.1f} seconds..."
            )

            # Wait before retrying
            await asyncio.sleep(wait_time)

    # This should never be reached, but just in case
    raise last_exception
