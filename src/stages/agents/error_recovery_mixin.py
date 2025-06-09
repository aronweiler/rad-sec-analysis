"""
Error recovery mixin for agentic stages.

Provides common error recovery patterns that can be reused across different agentic stages.
"""

from pydantic import ValidationError
from langchain_core.messages import HumanMessage


class ErrorRecoveryMixin:
    """Mixin providing common error recovery patterns for agentic stages"""

    def create_retry_message(self, available_tools: list[str]) -> HumanMessage:
        """
        Create a message to scold LLM for not calling tools

        Args:
            available_tools: List of available tool names

        Returns:
            HumanMessage with retry instruction
        """
        return HumanMessage(
            content=f"Invalid response! Please try again and ensure you call one of the available tools: {', '.join(available_tools)}."
        )

    def handle_validation_error(self, tool_name: str, error: ValidationError) -> str:
        """
        Handle validation errors consistently

        Args:
            tool_name: Name of the tool that had validation error
            error: The validation error that occurred

        Returns:
            Formatted error message for the LLM
        """
        return f"Validation error(s) when calling tool '{tool_name}': {str(error)}\n\nPlease correct the arguments and try again."

    def handle_tool_execution_error(self, tool_name: str, error: Exception) -> str:
        """
        Handle general tool execution errors

        Args:
            tool_name: Name of the tool that failed
            error: The exception that occurred

        Returns:
            Formatted error message for the LLM
        """
        return f"Error executing tool '{tool_name}': {str(error)}"

    def handle_mcp_tool_error(
        self, tool_name: str, server_name: str, error: Exception
    ) -> str:
        """
        Handle MCP tool execution errors

        Args:
            tool_name: Name of the MCP tool that failed
            server_name: Name of the MCP server
            error: The exception that occurred

        Returns:
            Formatted error message for the LLM
        """
        return f"Error executing MCP tool '{tool_name}' on server '{server_name}': {str(error)}"
