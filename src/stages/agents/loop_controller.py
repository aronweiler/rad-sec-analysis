"""
Agentic loop controller for managing the core execution loop.

Controls the agentic loop execution with error recovery and iteration management.
"""

import logging
from typing import Any, Awaitable, Callable, List, Optional, Tuple

from langchain.base_language import BaseLanguageModel
from langchain_core.messages import BaseMessage, AIMessage

from src.core.context_window_manager import ContextWindowManager
from src.models.stage_config import CompressionConfig

from .tool_manager import AgenticToolManager
from .error_recovery_mixin import ErrorRecoveryMixin


class ValidationRetryNeeded(Exception):
    """Exception raised when a validation error occurs and a retry is needed"""

    def __init__(self, message: str, validation_errors: Optional[List[str]] = None):
        super().__init__(message)
        self.validation_errors = validation_errors or []


class AgenticLoopController(ErrorRecoveryMixin):
    """Controls the agentic loop execution with error recovery and iteration management"""

    def __init__(
        self,
        logger: logging.Logger,
        max_iterations: int,
        context_window_manager: Optional[ContextWindowManager] = None,
        compression_config: Optional[CompressionConfig] = None,
        model_name: str = "default",
    ):
        """
        Initialize the loop controller

        Args:
            logger: Logger instance for this controller
            max_iterations: Maximum number of iterations before forced termination
            context_window_manager: Context window manager for compression
            compression_config: Configuration for context compression
            model_name: Model name for token counting
        """
        self.logger = logger
        self.max_iterations = max_iterations
        self.context_window_manager = context_window_manager
        self.compression_config = compression_config
        self.model_name = model_name

    async def execute_loop(
        self,
        llm_with_tools: BaseLanguageModel,
        messages: List[BaseMessage],
        tool_manager: AgenticToolManager,
        termination_checker: Callable[
            [AIMessage, Optional[Any]], Awaitable[Tuple[bool, Any]]
        ],
        forced_termination_handler: Callable[[], Awaitable[Any]],
        arg_injector: Callable[[dict], dict],
        termination_tool_names: Optional[List[str]] = None,
        current_iteration: int = 0,
        max_forced_retries: int = 3,
    ) -> Any:
        """
        Execute the main agentic loop with enhanced forced termination handling

        Args:
            llm_with_tools: LLM instance bound with tools
            messages: Current conversation messages
            tool_manager: Tool manager for executing tools
            termination_checker: Function to check if loop should terminate
            forced_termination_handler: Function to handle forced termination
            arg_injector: Function to inject arguments into tool calls
            termination_tool_names: List of tool names that indicate termination
            current_iteration: Current iteration number
            max_forced_retries: Maximum retries for forced termination validation errors

        Returns:
            Final result from the agentic loop
        """
        self.logger.info(
            f"Executing agentic loop iteration {current_iteration} (max: {self.max_iterations})"
        )

        # Apply context window management before LLM invocation
        processed_messages, was_compressed = await self._manage_context_window(
            messages, tool_manager
        )

        if was_compressed:
            self.logger.info("Context was compressed before LLM invocation")
            # Update the original messages list with compressed version
            messages.clear()
            messages.extend(processed_messages)

        # Get LLM response
        response = await llm_with_tools.ainvoke(messages)
        messages.append(response)

        # Handle case where LLM doesn't call any tools
        if not response.tool_calls:
            # Check if we've reached max iterations BEFORE handling no tool calls
            if current_iteration >= self.max_iterations:
                self.logger.warning(
                    f"Max iterations reached ({self.max_iterations}) with no tool calls, forcing termination"
                )
                return await self._handle_forced_termination_with_retries(
                    forced_termination_handler, max_forced_retries
                )

            self.logger.warning("LLM did not call any tools, handling retry")
            return await self._handle_no_tool_calls(
                response,
                llm_with_tools,
                messages,
                tool_manager,
                termination_checker,
                forced_termination_handler,
                arg_injector,
                termination_tool_names,
                current_iteration,
                max_forced_retries,
            )

        # Log tool calls
        tool_call_names = [call["name"] for call in response.tool_calls]
        self.logger.info(f"LLM called tools: {tool_call_names}")

        # Execute tools (always execute pending tool calls regardless of iteration count)
        tool_messages, termination_result, has_validation_error = (
            await tool_manager.execute_tools(
                response, arg_injector, termination_tool_names
            )
        )
        messages.extend(tool_messages)

        # Check for termination first (before checking iteration limits)
        should_terminate, result = await termination_checker(
            response, termination_result
        )
        if should_terminate:
            self.logger.info("Termination condition met, exiting loop")
            return result

        # NOW check if we've reached max iterations (after executing tools)
        if current_iteration >= self.max_iterations:
            self.logger.warning(
                f"Max iterations reached ({self.max_iterations}) after executing tools, forcing termination"
            )
            return await self._handle_forced_termination_with_retries(
                forced_termination_handler, max_forced_retries
            )

        # Continue loop if no validation errors, otherwise retry current iteration
        next_iteration = (
            current_iteration if has_validation_error else current_iteration + 1
        )

        if has_validation_error:
            self.logger.info("Validation error occurred, retrying current iteration")
        else:
            self.logger.info("Continuing to next iteration")

        return await self.execute_loop(
            llm_with_tools,
            messages,
            tool_manager,
            termination_checker,
            forced_termination_handler,
            arg_injector,
            termination_tool_names,
            next_iteration,
            max_forced_retries,
        )

    async def _manage_context_window(
        self, messages: List[BaseMessage], tool_manager: AgenticToolManager
    ) -> Tuple[List[BaseMessage], bool]:
        """
        Manage context window size through compression if needed

        Args:
            messages: Current conversation messages
            tool_manager: Tool manager for accessing available tools

        Returns:
            Tuple of (processed_messages, was_compressed)
        """
        # Skip if no context window manager or compression config
        if not self.context_window_manager or not self.compression_config:
            return messages, False

        # Get available tools for compression
        available_tools = {}
        if self.compression_config.compression_tool:
            # Get the compression tool from tool manager
            tool_names = tool_manager.get_tool_names()
            if self.compression_config.compression_tool in tool_names:
                tools_list = tool_manager.get_tools_list()
                for tool in tools_list:
                    if tool.name == self.compression_config.compression_tool:
                        available_tools[tool.name] = tool
                        break

        try:
            return await self.context_window_manager.manage_context_window(
                messages=messages,
                compression_config=self.compression_config,
                model_name=self.model_name,
                available_tools=available_tools,
            )
        except Exception as e:
            self.logger.error(f"Context window management failed: {e}")
            # Return original messages if compression fails
            return messages, False

    async def _handle_forced_termination_with_retries(
        self,
        forced_termination_handler: Callable[[], Awaitable[Any]],
        max_forced_retries: int,
    ) -> Any:
        """
        Handle forced termination with retry logic for validation errors

        Args:
            forced_termination_handler: Function to handle forced termination
            max_forced_retries: Maximum number of retries for validation errors

        Returns:
            Final result from forced termination

        Raises:
            ValueError: If forced termination fails after all retries
        """
        self.logger.info(
            f"Attempting forced termination with up to {max_forced_retries} retries"
        )

        for retry_attempt in range(max_forced_retries):
            try:
                result = await forced_termination_handler()
                if retry_attempt > 0:
                    self.logger.info(
                        f"Forced termination successful on retry attempt {retry_attempt + 1}"
                    )
                else:
                    self.logger.info("Forced termination successful on first attempt")
                return result

            except ValidationRetryNeeded as e:
                if retry_attempt < max_forced_retries - 1:
                    self.logger.warning(
                        f"Forced termination validation error on attempt {retry_attempt + 1}/{max_forced_retries}: {e}"
                    )
                    # Continue to next retry
                    continue
                else:
                    self.logger.error(
                        f"Max forced termination retries reached ({max_forced_retries}). Final error: {e}"
                    )
                    raise ValueError(
                        f"Forced termination failed validation after {max_forced_retries} attempts"
                    ) from e

            except Exception as e:
                # For non-validation errors, don't retry
                self.logger.error(
                    f"Forced termination failed with non-retryable error: {e}"
                )
                raise ValueError(f"Forced termination failed: {e}") from e

        # This should never be reached due to the loop logic above
        raise ValueError("Forced termination failed unexpectedly")

    async def _handle_no_tool_calls(
        self,
        response: AIMessage,
        llm_with_tools: BaseLanguageModel,
        messages: List[BaseMessage],
        tool_manager: AgenticToolManager,
        termination_checker: Callable[
            [AIMessage, Optional[Any]], Awaitable[Tuple[bool, Any]]
        ],
        forced_termination_handler: Callable[[], Awaitable[Any]],
        arg_injector: Callable[[dict], dict],
        termination_tool_names: Optional[List[str]],
        current_iteration: int,
        max_forced_retries: int = 3,
    ) -> Any:
        """
        Handle case where LLM doesn't call any tools (updated to include max_forced_retries)
        """
        # Create retry message
        retry_message = self.create_retry_message(tool_manager.get_tool_names())
        messages.extend([retry_message])

        # Apply context window management before retry
        processed_messages, was_compressed = await self._manage_context_window(
            messages, tool_manager
        )

        if was_compressed:
            self.logger.info("Context was compressed before retry LLM invocation")
            # Update the original messages list with compressed version
            messages.clear()
            messages.extend(processed_messages)

        # Get new response
        new_response = await llm_with_tools.ainvoke(messages)
        messages.append(new_response)

        # Increment iteration and continue loop
        return await self.execute_loop(
            llm_with_tools,
            messages,
            tool_manager,
            termination_checker,
            forced_termination_handler,
            arg_injector,
            termination_tool_names,
            current_iteration + 1,
            max_forced_retries,
        )
