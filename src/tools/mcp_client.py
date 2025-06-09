import logging
import asyncio
import json
from typing import Any, Optional, Dict, List, Union
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.sse import sse_client

from ..models.mcp_server_config import MCPServerConfig
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain.tools import BaseTool

logger = logging.getLogger(__name__)


class MCPClient:
    """
    Generic MCP client that can connect to any MCP server and dynamically discover
    and interact with tools, resources, and prompts.

    This client discovers tools at runtime through the MCP protocol's discovery mechanisms.
    """

    def __init__(
        self, server_url: str = "http://localhost:8000/sse", timeout: int = 30
    ):
        """
        Initialize the generic MCP client.

        Args:
            server_url: URL of the MCP server
            timeout: Connection timeout in seconds
        """
        self.server_url = server_url
        self.timeout = timeout
        self.session: Optional[ClientSession] = None
        self._connected = False

    @asynccontextmanager
    async def connect(self):
        """
        Async context manager for connecting to the MCP server.

        Usage:
            async with client.connect() as session:
                tools = await client.list_tools()
        """
        try:
            logger.info(f"🔗 Connecting to MCP server at {self.server_url}...")

            async with sse_client(url=self.server_url, timeout=self.timeout) as (
                read_stream,
                write_stream,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    self.session = session
                    await session.initialize()
                    self._connected = True
                    logger.info("✅ Connected to MCP Server")

                    yield session

        except Exception as e:
            logger.error(f"❌ Failed to connect: {e}")
            raise
        finally:
            self._connected = False
            self.session = None

    def _ensure_connected(self):
        """Ensure the client is connected before making requests."""
        if not self._connected or not self.session:
            raise RuntimeError(
                "Client is not connected. Use 'async with client.connect()' first."
            )

    async def list_tools(self) -> List[Dict[str, Any]]:
        """
        Discover and list all available tools on the server.

        Returns:
            List of tool information dictionaries with name, description, and schema
        """
        self._ensure_connected()

        try:
            result = await self.session.list_tools()
            tools = []
            if hasattr(result, "tools") and result.tools:
                for tool in result.tools:
                    tool_info = {
                        "name": tool.name,
                        "description": (
                            tool.description if hasattr(tool, "description") else None
                        ),
                    }
                    if hasattr(tool, "inputSchema"):
                        tool_info["input_schema"] = tool.inputSchema
                    tools.append(tool_info)
            return tools
        except Exception as e:
            raise RuntimeError(f"Failed to list tools: {e}")

    async def get_langchain_tools(self) -> list[BaseTool]:
        """
        Discover and return tools compatible with LangChain.

        Returns:
            List of LangChain-compatible tool dictionaries
        """
        tools = await load_mcp_tools(self.session)

        return tools

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any] = None) -> Any:
        """
        Call any tool by name with the provided arguments.

        Args:
            tool_name: Name of the tool to call
            arguments: Dictionary of arguments to pass to the tool

        Returns:
            Tool execution result
        """
        self._ensure_connected()

        try:
            result = await self.session.call_tool(tool_name, arguments or {})

            # Extract content from the result
            if hasattr(result, "content") and result.content:
                if len(result.content) == 1:
                    content = result.content[0]
                    if hasattr(content, "text"):
                        return content.text
                    else:
                        return content
                else:
                    # Multiple content items
                    return [
                        getattr(content, "text", content) for content in result.content
                    ]
            else:
                return result

        except Exception as e:
            raise RuntimeError(f"Failed to call tool '{tool_name}': {e}")

    async def list_resources(self) -> List[Dict[str, Any]]:
        """
        Discover and list all available resources on the server.

        Returns:
            List of resource information dictionaries
        """
        self._ensure_connected()

        try:
            result = await self.session.list_resources()
            resources = []
            if hasattr(result, "resources") and result.resources:
                for resource in result.resources:
                    resource_info = {
                        "uri": resource.uri,
                        "name": getattr(resource, "name", None),
                        "description": getattr(resource, "description", None),
                        "mime_type": getattr(resource, "mimeType", None),
                    }
                    resources.append(resource_info)
            return resources
        except Exception as e:
            raise RuntimeError(f"Failed to list resources: {e}")

    async def read_resource(self, uri: str) -> tuple[str, Optional[str]]:
        """
        Read a resource by its URI.

        Args:
            uri: URI of the resource to read

        Returns:
            Tuple of (content, mime_type)
        """
        self._ensure_connected()

        try:
            content, mime_type = await self.session.read_resource(uri)
            return content, mime_type
        except Exception as e:
            raise RuntimeError(f"Failed to read resource '{uri}': {e}")

    async def list_prompts(self) -> List[Dict[str, Any]]:
        """
        Discover and list all available prompts on the server.

        Returns:
            List of prompt information dictionaries
        """
        self._ensure_connected()

        try:
            result = await self.session.list_prompts()
            prompts = []
            if hasattr(result, "prompts") and result.prompts:
                for prompt in result.prompts:
                    prompt_info = {
                        "name": prompt.name,
                        "description": getattr(prompt, "description", None),
                        "arguments": [],
                    }
                    if hasattr(prompt, "arguments") and prompt.arguments:
                        for arg in prompt.arguments:
                            arg_info = {
                                "name": arg.name,
                                "description": getattr(arg, "description", None),
                                "required": getattr(arg, "required", False),
                            }
                            prompt_info["arguments"].append(arg_info)
                    prompts.append(prompt_info)
            return prompts
        except Exception as e:
            raise RuntimeError(f"Failed to list prompts: {e}")

    async def get_prompt(self, name: str, arguments: Dict[str, str] = None) -> Any:
        """
        Get a prompt by name with the provided arguments.

        Args:
            name: Name of the prompt
            arguments: Dictionary of arguments for the prompt

        Returns:
            Prompt result
        """
        self._ensure_connected()

        try:
            result = await self.session.get_prompt(name, arguments or {})
            return result
        except Exception as e:
            raise RuntimeError(f"Failed to get prompt '{name}': {e}")

    @property
    def is_connected(self) -> bool:
        """Check if client is connected"""
        return self._connected
