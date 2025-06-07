import logging
from abc import ABC, abstractmethod
from typing import Any

from src.core.llm_factory import LLMFactory
from src.models.application_config import ApplicationConfig
from src.models.stage_config import Stage
from src.tools.mcp_client_manager import MCPClientManager


class StageBase(ABC):
    """Base class for all stages in the analysis pipeline"""

    def __init__(
        self,
        config: ApplicationConfig,
        mcp_client_manager: MCPClientManager,
        stage_type: Stage,
    ):
        """
        Initialize the stage base class

        Args:
            config: Application configuration
            mcp_client_manager: MCP client manager for tool access
            stage_type: The specific stage type this instance represents
        """
        self.config = config
        self.mcp_client_manager = mcp_client_manager
        self.stage_type = stage_type
        self.stage_config = config.get_stage_config(stage_type)

        # Validate stage configuration
        if not self.stage_config:
            raise ValueError(f"{stage_type.value} stage not configured")

        # Initialize LLM if LLM config is provided
        if self.stage_config.llm_config:
            llm_factory = LLMFactory()
            self.llm = llm_factory.create_llm(config=self.stage_config.llm_config)
        else:
            self.llm = None

        # Initialize logger
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    async def run(self, *args, **kwargs) -> Any:
        """
        Abstract method for running the stage

        This method must be implemented by each concrete stage class to define
        the specific workflow and logic for that stage.

        Args:
            *args: Variable positional arguments specific to the stage
            **kwargs: Variable keyword arguments specific to the stage

        Returns:
            Any: The result of the stage execution, specific to each stage
        """
        pass
