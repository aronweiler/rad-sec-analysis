"""
Tool Manager

Manages registration and retrieval of LangChain tools across the application.
Provides a centralized registry for all available tools.
"""

import logging
from typing import Dict, List, Optional, Callable, Any, Union
from langchain.tools import BaseTool
from langchain.tools.base import Tool

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Registry for managing LangChain tools"""
    
    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self._tool_functions: Dict[str, Callable] = {}
        
    def register_tool(self, tool: BaseTool) -> None:
        """
        Register a LangChain tool.
        
        Args:
            tool: LangChain tool instance to register
        """
        if not isinstance(tool, BaseTool):
            raise ValueError(f"Tool must be a LangChain BaseTool instance")
        
        tool_name = tool.name
        self._tools[tool_name] = tool
          # Store the function reference if available
        if hasattr(tool, 'func') and callable(getattr(tool, 'func', None)):
            self._tool_functions[tool_name] = getattr(tool, 'func')
        
        logger.info(f"Registered tool: {tool_name}")
    
    def register_tool_function(self, name: str, func: Callable) -> None:
        """
        Register a tool function directly.
        
        Args:
            name: Name of the tool function
            func: Callable function to register
        """
        if not callable(func):
            raise ValueError(f"Function must be callable")
        
        self._tool_functions[name] = func
        logger.info(f"Registered tool function: {name}")
    
    def get_tool(self, tool_name: str) -> Optional[BaseTool]:
        """
        Get a tool instance by name.
        
        Args:
            tool_name: Name of the tool to get
            
        Returns:
            Tool instance or None if not found
        """
        return self._tools.get(tool_name)
    
    def get_tool_function(self, tool_name: str) -> Optional[Callable]:
        """
        Get a tool function by name.
        
        Args:
            tool_name: Name of the tool function to get
            
        Returns:
            Tool function or None if not found
        """
        return self._tool_functions.get(tool_name)
    
    def get_tool_or_function(self, tool_name: str) -> Optional[Union[BaseTool, Callable]]:
        """
        Get either a tool instance or function by name.
        Prioritizes tool instances over functions.
        
        Args:
            tool_name: Name of the tool to get
            
        Returns:
            Tool instance, function, or None if not found
        """
        tool = self.get_tool(tool_name)
        if tool:
            return tool
        return self.get_tool_function(tool_name)
    
    def list_tools(self) -> List[str]:
        """Get list of registered tool names"""
        all_tools = set(self._tools.keys()) | set(self._tool_functions.keys())
        return list(all_tools)
    
    def list_tool_instances(self) -> List[str]:
        """Get list of registered tool instance names"""
        return list(self._tools.keys())
    
    def list_tool_functions(self) -> List[str]:
        """Get list of registered tool function names"""
        return list(self._tool_functions.keys())
    
    def get_tools_by_names(self, tool_names: List[str]) -> List[BaseTool]:
        """
        Get multiple tools by their names.
        
        Args:
            tool_names: List of tool names to retrieve
            
        Returns:
            List of available tool instances (skips missing tools)
        """
        tools = []
        for name in tool_names:
            tool = self.get_tool(name)
            if tool:
                tools.append(tool)
            else:
                logger.warning(f"Tool not found: {name}")
        return tools
    
    def get_all_tools(self) -> List[BaseTool]:
        """Get all registered tool instances"""
        return list(self._tools.values())
    
    def has_tool(self, tool_name: str) -> bool:
        """Check if a tool is registered"""
        return tool_name in self._tools or tool_name in self._tool_functions
    
    def unregister_tool(self, tool_name: str) -> bool:
        """
        Unregister a tool by name.
        
        Args:
            tool_name: Name of the tool to unregister
            
        Returns:
            True if tool was found and removed, False otherwise
        """
        removed = False
        
        if tool_name in self._tools:
            del self._tools[tool_name]
            removed = True
        
        if tool_name in self._tool_functions:
            del self._tool_functions[tool_name]
            removed = True
        
        if removed:
            logger.info(f"Unregistered tool: {tool_name}")
        
        return removed
    
    def clear_registry(self) -> None:
        """Clear all registered tools"""
        self._tools.clear()
        self._tool_functions.clear()
        logger.info("Cleared tool registry")


# Global tool registry instance
_tool_registry = None


def get_tool_registry() -> ToolRegistry:
    """Get or create the global tool registry instance"""
    global _tool_registry
    if _tool_registry is None:
        _tool_registry = ToolRegistry()
        # Auto-register available tools
        _register_default_tools()
    return _tool_registry


def _register_default_tools():
    """Register default tools from nvd_tool_wrappers"""
    try:
        from .nvd_tool_wrappers import nvd_tools
        from .submit_analysis_tool import submit_analysis_tools
        
        # Register all tools
        tools_to_register = nvd_tools + submit_analysis_tools
        
        registry = get_tool_registry()
        
        # Register NVD tools
        for tool in tools_to_register:
            if isinstance(tool, BaseTool):
                registry.register_tool(tool)            
            elif callable(tool):
                # Register as function if it's not a BaseTool instance
                tool_name = getattr(tool, 'name', None) or tool.__name__
                if tool_name:
                    registry.register_tool_function(tool_name, tool)
                    
        
        logger.info(f"Registered {len(tools_to_register)} tools")
        
    except ImportError as e:
        logger.warning(f"Could not import tools: {e}")
    except Exception as e:
        logger.error(f"Error registering default tools: {e}")


def register_tools_from_module(module_name: str, tools_attr: str = "tools") -> None:
    """
    Register tools from a module.
    
    Args:
        module_name: Name of the module to import
        tools_attr: Name of the attribute containing the tools list
    """
    try:
        import importlib
        module = importlib.import_module(module_name)
        tools = getattr(module, tools_attr, [])
        
        registry = get_tool_registry()
        
        for tool in tools:
            if isinstance(tool, BaseTool):
                registry.register_tool(tool)
            elif callable(tool):
                tool_name = getattr(tool, 'name', tool.__name__)
                registry.register_tool_function(tool_name, tool)
        
        logger.info(f"Registered {len(tools)} tools from {module_name}")
        
    except Exception as e:
        logger.error(f"Error registering tools from {module_name}: {e}")


# Convenience functions for easy access
def get_tool(tool_name: str) -> Optional[BaseTool]:
    """Get a tool instance by name"""
    return get_tool_registry().get_tool(tool_name)


def get_tool_function(tool_name: str) -> Optional[Callable]:
    """Get a tool function by name"""
    return get_tool_registry().get_tool_function(tool_name)


def get_tool_or_function(tool_name: str) -> Optional[Union[BaseTool, Callable]]:
    """Get either a tool instance or function by name"""
    return get_tool_registry().get_tool_or_function(tool_name)


def list_available_tools() -> List[str]:
    """Get list of all available tool names"""
    return get_tool_registry().list_tools()


def register_tool(tool: BaseTool) -> None:
    """Register a tool instance"""
    get_tool_registry().register_tool(tool)


def register_tool_function(name: str, func: Callable) -> None:
    """Register a tool function"""
    get_tool_registry().register_tool_function(name, func)


def has_tool(tool_name: str) -> bool:
    """Check if a tool is available"""
    return get_tool_registry().has_tool(tool_name)


def get_tools_for_stage(stage_tools: Optional[List[str]] = None) -> List[BaseTool]:
    """
    Get tools for a specific stage.
    
    Args:
        stage_tools: List of tool names for the stage. If None, returns all tools.
        
    Returns:
        List of available tools for the stage
    """
    registry = get_tool_registry()
    
    if stage_tools is None:
        return registry.get_all_tools()
    
    return registry.get_tools_by_names(stage_tools)