"""
Abstract base class for agentic stages.

Provides a common framework for stages that use agentic LLM loops with tools.
"""

from abc import ABC, abstractmethod
from typing import Any, List, Optional, Tuple

from langchain_core.messages import BaseMessage, AIMessage

from src.core.context_window_manager import ContextWindowManager
from src.core.llm_factory import LLMFactory
from src.core.token_manager import TokenCounter
from src.models.application_config import ApplicationConfig
from src.models.stage_config import Stage
from src.stages.base import StageBase
from src.tools.mcp_client_manager import MCPClientManager

from .error_recovery_mixin import ErrorRecoveryMixin
from .tool_manager import AgenticToolManager
from .loop_controller import AgenticLoopController


class AgenticStageBase(StageBase, ErrorRecoveryMixin, ABC):
    """Base class for stages that use agentic LLM loops with tools"""
    
    def __init__(
        self, 
        config: ApplicationConfig, 
        mcp_client_manager: MCPClientManager, 
        stage_type: Stage
    ):
        """
        Initialize the agentic stage

        Args:
            config: Application configuration
            mcp_client_manager: Manager for MCP client connections
            stage_type: Type of stage this represents
        """
        super().__init__(config, mcp_client_manager, stage_type)
        self.tool_manager = AgenticToolManager(self.logger, mcp_client_manager)

        # Initialize context window management
        self.token_counter = TokenCounter()
        self.llm_factory = LLMFactory()
        self.context_window_manager = ContextWindowManager(
            self.token_counter, 
            self.llm_factory
        )

        # Create loop controller with context management
        self.loop_controller = AgenticLoopController(
            logger=self.logger,
            max_iterations=self.stage_config.max_iterations,
            context_window_manager=self.context_window_manager,
            compression_config=self.stage_config.compression_config,
            model_name=self.stage_config.llm_config.model_name if self.stage_config.llm_config else "default"
        )

        self.messages: List[BaseMessage] = []
    
    async def execute_agentic_workflow(self, **kwargs) -> Any:
        """
        Main entry point for agentic workflow execution
        
        Args:
            **kwargs: Stage-specific arguments passed to abstract methods
            
        Returns:
            Final result from the agentic workflow
        """
        self.logger.info(f"Starting agentic workflow for {self.stage_type}")
        
        # Initialize tools
        await self.tool_manager.initialize_tools(
            self.stage_config, 
            self.get_required_tools()
        )
        
        # Prepare initial messages
        self.messages = await self._prepare_initial_messages(**kwargs)
        
        # Create LLM with tools
        llm_with_tools = self.llm.bind_tools(self.tool_manager.get_tools_list())
        
        # get the max_forced_retries from the stage config
        max_forced_retries = self.stage_config.max_final_retries or 3
        
        # Execute the loop
        result = await self.loop_controller.execute_loop(
            llm_with_tools=llm_with_tools,
            messages=self.messages,
            tool_manager=self.tool_manager,
            termination_checker=lambda resp, term_result: self._should_terminate(resp, term_result, **kwargs),
            forced_termination_handler=lambda: self._handle_forced_termination(**kwargs),
            arg_injector=lambda args: self._inject_stage_specific_args(args, **kwargs),
            termination_tool_names=self.get_termination_tool_names(),
            max_forced_retries=max_forced_retries,
        )
        
        self.logger.info(f"Completed agentic workflow for {self.stage_type}")
        return result
    
    @abstractmethod
    async def _prepare_initial_messages(self, **kwargs) -> List[BaseMessage]:
        """
        Prepare the initial system and user messages for the stage
        
        Args:
            **kwargs: Stage-specific arguments
            
        Returns:
            List of initial messages to start the conversation
        """
        pass
    
    @abstractmethod
    async def _should_terminate(self, response: AIMessage, termination_result: Optional[Any], **kwargs) -> Tuple[bool, Any]:
        """
        Check if the loop should terminate and return the result
        
        Args:
            response: The AI response from the current iteration
            termination_result: Result from any termination tools that were called
            **kwargs: Stage-specific arguments
            
        Returns:
            Tuple of (should_terminate: bool, final_result: Any)
        """
        pass
    
    @abstractmethod
    async def _handle_forced_termination(self, **kwargs) -> Any:
        """
        Handle forced termination when max iterations are reached
        
        Args:
            **kwargs: Stage-specific arguments
            
        Returns:
            Final result when forced to terminate
        """
        pass
    
    @abstractmethod
    def _inject_stage_specific_args(self, tool_args: dict, **kwargs) -> dict:
        """
        Inject stage-specific arguments into tool calls
        
        Args:
            tool_args: Original tool arguments from the LLM
            **kwargs: Stage-specific arguments
            
        Returns:
            Enhanced tool arguments with injected data
        """
        pass
    
    @abstractmethod
    def get_required_tools(self) -> List[str]:
        """
        Return list of tools that must be available for this stage
        
        Returns:
            List of required tool names
        """
        pass
    
    def get_termination_tool_names(self) -> List[str]:
        """
        Return list of tool names that indicate the stage should terminate
        
        Override this method if your stage has specific termination tools.
        Default implementation returns empty list (no automatic termination).
        
        Returns:
            List of termination tool names
        """
        return []
    
    def get_conversation_messages(self) -> List[BaseMessage]:
        """
        Get the current conversation messages
        
        Returns:
            List of messages from the current conversation
        """
        return self.messages.copy()
    
    def get_available_tool_names(self) -> List[str]:
        """
        Get list of currently available tool names
        
        Returns:
            List of available tool names
        """
        return self.tool_manager.get_tool_names()