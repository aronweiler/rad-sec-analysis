import logging
from typing import Dict, Any, List, Optional, Tuple
from contextlib import asynccontextmanager

from .mcp_client import MCPClient
from src.models.mcp_server_config import MCPServerConfig
from langchain.tools import BaseTool

logger = logging.getLogger(__name__)


class MCPClientManager:
    """Manages multiple MCP clients using GenericMCPClient"""

    def __init__(self):
        self.clients: Dict[str, MCPClient] = {}
        self.server_configs: Dict[str, MCPServerConfig] = {}
        self._initialized = False

    def _build_server_url(self, config: MCPServerConfig) -> str:
        """Build server URL from MCPServerConfig"""
        if config.transport_type.lower() == "sse":
            return f"http://{config.host}:{config.port}/sse"
        elif config.transport_type.lower() in ["streamable_http", "http"]:
            return f"http://{config.host}:{config.port}/sse"  # GenericMCPClient uses SSE endpoint
        else:
            # Default to SSE for any other transport type
            return f"http://{config.host}:{config.port}/sse"

    async def initialize(self, server_configs: Dict[str, MCPServerConfig]):
        """
        Initialize MCP clients for all configured servers

        Args:
            server_configs: Server configurations from config
        """
        self.server_configs = server_configs

        for name, config in server_configs.items():
            if config.enabled:
                # Build server URL from config
                server_url = self._build_server_url(config)

                # Create client
                client = MCPClient(server_url=server_url, timeout=config.timeout)
                self.clients[name] = client

                logger.info(f"Created MCP client for {name} at {server_url}")

        self._initialized = True
        logger.info(f"MCP Client Manager initialized with {len(self.clients)} clients")

    async def shutdown(self):
        """Shutdown all MCP clients"""
        # Note: GenericMCPClient doesn't maintain persistent connections
        # Connections are managed via context managers
        self.clients.clear()
        self.server_configs.clear()
        self._initialized = False
        logger.info("MCP Client Manager shutdown complete")

    def get_client(self, server_name: str) -> Optional[MCPClient]:
        """Get a specific MCP client"""
        return self.clients.get(server_name)

    @asynccontextmanager
    async def get_connected_client(self, server_name: str):
        """Get a connected client using context manager"""
        client = self.get_client(server_name)
        if not client:
            raise RuntimeError(f"No client available for server {server_name}")

        async with client.connect() as session:
            yield client

    async def call_tool(
        self, server_name: str, tool_name: str, arguments: Dict[str, Any] = {}
    ) -> Any:
        """Call a tool on a specific server"""
        async with self.get_connected_client(server_name) as client:
            return await client.call_tool(tool_name, arguments or {})

    async def list_tools(self, server_name: str) -> List[Dict[str, Any]]:
        """List all available tools for a specific server"""
        async with self.get_connected_client(server_name) as client:
            return await client.list_tools()

    async def get_langchain_tools(self, server_name: str) -> list[BaseTool]:
        """Get LangChain-compatible tools for a specific server"""
        async with self.get_connected_client(server_name) as client:
            return await client.get_langchain_tools()

    async def get_all_available_tools(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all available tools across all servers"""
        tools = {}
        for server_name in self.clients.keys():
            try:
                tools[server_name] = await self.list_tools(server_name)
            except Exception as e:
                logger.error(f"Failed to get tools for {server_name}: {e}")
                tools[server_name] = []
        return tools

    async def list_resources(self, server_name: str) -> List[Dict[str, Any]]:
        """List all available resources for a specific server"""
        async with self.get_connected_client(server_name) as client:
            return await client.list_resources()

    async def read_resource(
        self, server_name: str, uri: str
    ) -> Tuple[str, Optional[str]]:
        """Read a resource from a specific server"""
        async with self.get_connected_client(server_name) as client:
            return await client.read_resource(uri)

    async def list_prompts(self, server_name: str) -> List[Dict[str, Any]]:
        """List all available prompts for a specific server"""
        async with self.get_connected_client(server_name) as client:
            return await client.list_prompts()

    async def get_prompt(
        self, server_name: str, name: str, arguments: Dict[str, str] = {}
    ) -> Any:
        """Get a prompt from a specific server"""
        async with self.get_connected_client(server_name) as client:
            return await client.get_prompt(name, arguments or {})

    async def test_connections(self) -> Dict[str, bool]:
        """Test connections to all configured servers"""
        results = {}
        for server_name in self.clients.keys():
            try:
                async with self.get_connected_client(server_name) as client:
                    # Try to list tools as a connection test
                    await client.list_tools()
                    results[server_name] = True
                    logger.info(f"✅ Connection test successful for {server_name}")
            except Exception as e:
                results[server_name] = False
                logger.error(f"❌ Connection test failed for {server_name}: {e}")
        return results

    @asynccontextmanager
    async def managed_session(self, server_configs: Dict[str, MCPServerConfig]):
        """Context manager for MCP client session"""
        try:
            await self.initialize(server_configs)
            yield self
        finally:
            await self.shutdown()

    @property
    def is_initialized(self) -> bool:
        """Check if manager is initialized"""
        return self._initialized

    @property
    def available_servers(self) -> List[str]:
        """Get list of available server names"""
        return list(self.clients.keys())

    def get_server_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all configured servers"""
        info = {}
        for server_name, config in self.server_configs.items():
            client = self.clients.get(server_name)
            info[server_name] = {
                "name": config.name,
                "host": config.host,
                "port": config.port,
                "transport_type": config.transport_type,
                "timeout": config.timeout,
                "enabled": config.enabled,
                "server_url": client.server_url if client else None,
            }
        return info
