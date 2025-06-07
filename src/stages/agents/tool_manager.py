"""
Tool manager for agentic stages.

Handles tool initialization, execution, and result management for agentic workflows.
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from pydantic import ValidationError
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool

from src.tools.lc_tools.tool_manager import get_tool
from src.tools.mcp_client_manager import MCPClientManager
from .error_recovery_mixin import ErrorRecoveryMixin


class AgenticToolManager(ErrorRecoveryMixin):
    """Manages tool initialization, execution, and result handling for agentic stages"""
    
    def __init__(self, logger: logging.Logger, mcp_client_manager: MCPClientManager):
        """
        Initialize the tool manager
        
        Args:
            logger: Logger instance for this manager
            mcp_client_manager: Manager for MCP client connections
        """
        self.logger = logger
        self.mcp_client_manager = mcp_client_manager
        self.available_tools: Dict[str, BaseTool] = {}
        self.mcp_tools_to_server: Dict[str, str] = {}
    
    async def initialize_tools(self, stage_config, required_tools: Optional[List[str]] = None):
        """
        Initialize tools from config and verify required tools exist
        
        Args:
            stage_config: Stage configuration containing tool specifications
            required_tools: List of tool names that must be available
            
        Raises:
            ValueError: If required tools are not found
        """
        # Clear existing tools
        self.available_tools.clear()
        self.mcp_tools_to_server.clear()
        
        # Add available tools by config
        if stage_config.available_tools:
            for tool_name in stage_config.available_tools:
                tool = get_tool(tool_name)
                if tool:
                    self.available_tools[tool_name] = tool
                    self.logger.info(f"Added tool: {tool.name}")
                else:
                    self.logger.warning(f"Tool {tool_name} not found in config")

        # Add MCP tools if available
        if stage_config.available_mcp_servers:
            for server_name in stage_config.available_mcp_servers:
                try:
                    mcp_tools = await self.mcp_client_manager.get_langchain_tools(
                        server_name
                    )
                    for tool in mcp_tools:
                        self.available_tools[tool.name] = tool
                        self.mcp_tools_to_server[tool.name] = server_name
                        self.logger.info(
                            f"Added MCP tool: {tool.name} from {server_name}"
                        )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to get tools from MCP server {server_name}: {e}"
                    )
        
        # Verify required tools are available
        if required_tools:
            missing_tools = []
            for tool_name in required_tools:
                if tool_name not in self.available_tools:
                    missing_tools.append(tool_name)
            
            if missing_tools:
                raise ValueError(f"Required tools not found: {', '.join(missing_tools)}")
    
    async def execute_tools(
        self, 
        response: AIMessage, 
        arg_injector: Callable[[dict], dict],
        termination_tool_names: Optional[List[str]] = None
    ) -> Tuple[List[ToolMessage], Optional[Any], bool]:
        """
        Execute tools and return messages and any termination result
        
        Args:
            response: AI response containing tool calls
            arg_injector: Function to inject additional arguments into tool calls
            termination_tool_names: List of tool names that indicate termination
            
        Returns:
            Tuple of (tool_messages, termination_result, has_validation_error)
        """
        tool_results = []
        termination_result = None
        has_validation_error = False
        termination_tool_names = termination_tool_names or []

        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]

            # Check if this is an MCP tool
            is_mcp_tool = tool_name in self.mcp_tools_to_server.keys()
            
            if is_mcp_tool:
                result = await self._execute_mcp_tool(tool_name, tool_args)
            else:
                result, tool_termination_result, validation_error = await self._execute_langchain_tool(
                    tool_name, tool_args, arg_injector, termination_tool_names
                )
                
                if validation_error:
                    has_validation_error = True
                
                if tool_termination_result is not None:
                    termination_result = tool_termination_result

            tool_results.append(
                ToolMessage(content=str(result), tool_call_id=tool_call["id"])
            )

        return tool_results, termination_result, has_validation_error
    
    async def _execute_mcp_tool(self, tool_name: str, tool_args: dict) -> str:
        """
        Execute an MCP tool
        
        Args:
            tool_name: Name of the MCP tool
            tool_args: Arguments for the tool
            
        Returns:
            Tool execution result as string
        """
        mcp_server = self.mcp_tools_to_server[tool_name]
        self.logger.info(f"Executing MCP tool: {tool_name} on server {mcp_server}")
        
        try:
            result = await self.mcp_client_manager.call_tool(
                mcp_server, tool_name, tool_args
            )
            return str(result)
        except Exception as e:
            return self.handle_mcp_tool_error(tool_name, mcp_server, e)
    
    async def _execute_langchain_tool(
        self, 
        tool_name: str, 
        tool_args: dict, 
        arg_injector: Callable[[dict], dict],
        termination_tool_names: List[str]
    ) -> Tuple[str, Optional[Any], bool]:
        """
        Execute a LangChain tool
        
        Args:
            tool_name: Name of the tool
            tool_args: Arguments for the tool
            arg_injector: Function to inject additional arguments
            termination_tool_names: List of termination tool names
            
        Returns:
            Tuple of (result_string, termination_result, has_validation_error)
        """
        self.logger.info(f"Executing tool: {tool_name}")
        
        # Find the tool
        tool = self.available_tools.get(tool_name)
        if not tool:
            return f"Error: Tool '{tool_name}' not found", None, False
        
        try:
            # Inject additional arguments
            enhanced_tool_args = arg_injector(tool_args)
            
            # Execute the tool - support both sync and async
            if tool.coroutine:
                result = await tool.ainvoke(enhanced_tool_args)
            else:
                result = tool.invoke(enhanced_tool_args)
            
            # Check if this was a termination tool
            termination_result = None
            if tool_name in termination_tool_names:
                termination_result = result
                self.logger.info(f"Termination tool '{tool_name}' executed successfully")
            
            return str(result), termination_result, False
            
        except ValidationError as ve:
            # Handle validation errors specifically
            error_msg = self.handle_validation_error(tool_name, ve)
            return error_msg, None, True
            
        except Exception as e:
            error_msg = self.handle_tool_execution_error(tool_name, e)
            self.logger.error(error_msg)
            return error_msg, None, False
    
    def get_tool_names(self) -> List[str]:
        """
        Get list of available tool names for error messages
        
        Returns:
            List of available tool names
        """
        return list(self.available_tools.keys())
    
    def get_tools_list(self) -> List[BaseTool]:
        """
        Get list of available tools for binding to LLM
        
        Returns:
            List of available BaseTool instances
        """
        return list(self.available_tools.values())