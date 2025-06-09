"""
Configuration Loader

Loads and validates application configuration from various sources.
"""

import os
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from pydantic import ValidationError

from ..models.application_config import ApplicationConfig
from ..models.llm_config import LLMConfig, LLMProvider
from ..models.mcp_server_config import (
    MCPServerConfig,
)
from ..models.stage_config import Stage, StageConfig

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Configuration loading error"""

    pass


class ConfigLoader:
    """Loads and validates application configuration"""

    def __init__(self):
        self.config: Optional[ApplicationConfig] = None

    def load_from_file(self, config_path: Union[str, Path]) -> ApplicationConfig:
        """Load configuration from file"""
        config_path = Path(config_path)

        if not config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")

        try:
            if config_path.suffix.lower() in [".yaml", ".yml"]:
                with open(config_path, "r") as f:
                    config_data = yaml.safe_load(f)
            elif config_path.suffix.lower() == ".json":
                with open(config_path, "r") as f:
                    config_data = json.load(f)
            else:
                raise ConfigurationError(
                    f"Unsupported config file format: {config_path.suffix}"
                )

            return self._validate_and_create_config(config_data)

        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ConfigurationError(f"Failed to parse config file: {e}")
        except ValidationError as e:
            raise ConfigurationError(f"Configuration validation failed: {e}")

    def load_from_dict(self, config_data: Dict[str, Any]) -> ApplicationConfig:
        """Load configuration from dictionary"""
        return self._validate_and_create_config(config_data)

    def _validate_and_create_config(
        self, config_data: Dict[str, Any]
    ) -> ApplicationConfig:
        """Validate and create ApplicationConfig from data"""
        try:
            # Process stages
            if "stages" in config_data:
                processed_stages = {}
                for stage_name, stage_config in config_data["stages"].items():
                    # Convert string stage names to enum
                    if isinstance(stage_name, str):
                        stage_enum = Stage(stage_name)
                    else:
                        stage_enum = stage_name

                    # Ensure stage field matches the key
                    stage_config["stage"] = stage_enum

                    # Create LLMConfig if needed
                    if "llm_config" in stage_config:
                        llm_data = stage_config["llm_config"]
                        if isinstance(llm_data, dict):
                            # Convert provider string to enum if needed
                            if "provider" in llm_data and isinstance(
                                llm_data["provider"], str
                            ):
                                llm_data["provider"] = LLMProvider(llm_data["provider"])
                            stage_config["llm_config"] = LLMConfig(**llm_data)

                    processed_stages[stage_enum] = StageConfig(**stage_config)

                config_data["stages"] = processed_stages

            # Process MCP servers
            if "mcp_servers" in config_data:
                processed_servers = {}
                for server_name, server_config in config_data["mcp_servers"].items():
                    processed_servers[server_name] = MCPServerConfig(**server_config)
                config_data["mcp_servers"] = processed_servers

            # Create and validate the main config
            config = ApplicationConfig(**config_data)
            self.config = config

            logger.info("Configuration loaded and validated successfully")
            return config

        except ValidationError as e:
            logger.error(f"Configuration validation failed: {e}")
            raise ConfigurationError(f"Invalid configuration: {e}")

    def _serialize_config_for_export(self, config: ApplicationConfig) -> Dict[str, Any]:
        """Convert config to a serializable dictionary with proper enum handling"""
        config_dict = config.model_dump()

        # Convert stages with enum keys to string keys
        if "stages" in config_dict:
            stages_dict = {}
            for stage_key, stage_config in config_dict["stages"].items():
                # Convert enum key to string
                if hasattr(stage_key, "value"):
                    string_key = stage_key.value
                else:
                    string_key = str(stage_key)

                # Convert enum values within the stage config
                if "stage" in stage_config and hasattr(stage_config["stage"], "value"):
                    stage_config["stage"] = stage_config["stage"].value

                if (
                    "llm_config" in stage_config
                    and "provider" in stage_config["llm_config"]
                ):
                    if hasattr(stage_config["llm_config"]["provider"], "value"):
                        stage_config["llm_config"]["provider"] = stage_config[
                            "llm_config"
                        ]["provider"].value

                stages_dict[string_key] = stage_config

            config_dict["stages"] = stages_dict

        return config_dict

    def save_config(
        self, config_path: Union[str, Path], config: Optional[ApplicationConfig] = None
    ):
        """Save configuration to file"""
        config = config or self.config
        if not config:
            raise ConfigurationError("No configuration to save")

        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dict for serialization with proper enum handling
        config_dict = self._serialize_config_for_export(config)

        try:
            if config_path.suffix.lower() in [".yaml", ".yml"]:
                with open(config_path, "w") as f:
                    yaml.dump(
                        config_dict,
                        f,
                        default_flow_style=False,
                        indent=2,
                        sort_keys=False,
                    )
            elif config_path.suffix.lower() == ".json":
                with open(config_path, "w") as f:
                    json.dump(config_dict, f, indent=2, default=str)
            else:
                raise ConfigurationError(
                    f"Unsupported config file format: {config_path.suffix}"
                )

            logger.info(f"Configuration saved to {config_path}")

        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ConfigurationError(f"Failed to save config file: {e}")

    def get_config(self) -> Optional[ApplicationConfig]:
        """Get current configuration"""
        return self.config

    def validate_config(self, config: ApplicationConfig) -> bool:
        """Validate configuration completeness"""
        try:
            # Check required stages
            required_stages = {
                Stage.INCIDENT_ANALYSIS,
                Stage.PRIORITIZED_RISK_AND_IMPACT_ASSESSMENT,
                Stage.FINAL_INCIDENT_ANALYSIS,
            }

            configured_stages = set(config.stages.keys())
            missing_stages = required_stages - configured_stages

            if missing_stages:
                logger.error(f"Missing required stages: {missing_stages}")
                return False

            # Check LLM configurations
            for stage, stage_config in config.stages.items():
                if (
                    not stage_config.llm_config.api_key
                    and stage_config.llm_config.provider
                    in [LLMProvider.OPENAI, LLMProvider.ANTHROPIC]
                ):
                    logger.warning(
                        f"No API key configured for {stage_config.llm_config.provider} in stage {stage}"
                    )

            # Check MCP servers
            if not config.mcp_servers:
                logger.warning("No MCP servers configured")

            logger.info("Configuration validation passed")
            return True

        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            return False


def load_config(config_path: Optional[Union[str, Path]] = None) -> ApplicationConfig:
    """Convenience function to load configuration"""
    loader = ConfigLoader()

    if config_path:
        return loader.load_from_file(config_path)

    raise ConfigurationError("No configuration path provided")
