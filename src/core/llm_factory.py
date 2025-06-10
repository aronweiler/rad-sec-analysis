"""
LLM Factory

Factory class for creating LLM instances based on configuration.
Supports multiple providers: OpenAI, Anthropic, Azure OpenAI, Google, Ollama, HuggingFace.
"""

import logging
from typing import Optional, Dict, Any
from langchain_core.language_models import BaseLanguageModel

from ..models.llm_config import LLMConfig, LLMProvider

logger = logging.getLogger(__name__)


class LLMFactory:
    """Factory for creating LLM instances based on configuration"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def create_llm(self, config: LLMConfig) -> BaseLanguageModel:
        """
        Create an LLM instance based on the provided configuration
        
        Args:
            config: LLM configuration object
            
        Returns:
            Configured LLM instance
            
        Raises:
            ValueError: If the provider is not supported
            ImportError: If required dependencies are not installed
        """
        self.logger.info(f"Creating LLM: {config.provider} - {config.model_name}")
        
        if config.provider == LLMProvider.OPENAI:
            return self._create_openai_llm(config)
        elif config.provider == LLMProvider.ANTHROPIC:
            return self._create_anthropic_llm(config)
        elif config.provider == LLMProvider.AZURE_OPENAI:
            return self._create_azure_openai_llm(config)
        elif config.provider == LLMProvider.GOOGLE:
            return self._create_google_llm(config)
        elif config.provider == LLMProvider.OLLAMA:
            return self._create_ollama_llm(config)
        elif config.provider == LLMProvider.HUGGINGFACE:
            return self._create_huggingface_llm(config)
        else:
            raise ValueError(f"Unsupported LLM provider: {config.provider}")
    
    def _create_openai_llm(self, config: LLMConfig) -> BaseLanguageModel:
        """Create OpenAI LLM instance"""
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            raise ImportError("langchain-openai is required for OpenAI provider")
        
        # Build parameters
        params = {
            "model": config.model_name,
            "temperature": config.temperature,
            "timeout": config.timeout,
            "max_retries": 0, # disabled in favor of my own retries config.max_retries,
        }
        
        # Add optional parameters
        if config.max_tokens:
            params["max_tokens"] = config.max_tokens
        if config.api_key:
            params["api_key"] = config.api_key
        if config.api_base:
            params["base_url"] = config.api_base
        
        # Add extra parameters
        params.update(config.extra_params)
        
        return ChatOpenAI(**params)
    
    def _create_anthropic_llm(self, config: LLMConfig) -> BaseLanguageModel:
        """Create Anthropic LLM instance"""
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError:
            raise ImportError("langchain-anthropic is required for Anthropic provider")
        
        # Build parameters
        params = {
            "model": config.model_name,
            "temperature": config.temperature,
            "timeout": config.timeout,
            "max_retries": 0, # disabled in favor of my own retries config.max_retries,
        }
        
        # Add optional parameters
        if config.max_tokens:
            params["max_tokens"] = config.max_tokens
        if config.api_key:
            params["api_key"] = config.api_key
        if config.api_base:
            params["base_url"] = config.api_base
        
        # Add extra parameters
        params.update(config.extra_params)
        
        return ChatAnthropic(**params)
    
    def _create_azure_openai_llm(self, config: LLMConfig) -> BaseLanguageModel:
        """Create Azure OpenAI LLM instance"""
        try:
            from langchain_openai import AzureChatOpenAI
        except ImportError:
            raise ImportError("langchain-openai is required for Azure OpenAI provider")
        
        # Build parameters
        params = {
            "deployment_name": config.model_name,
            "temperature": config.temperature,
            "timeout": config.timeout,
            "max_retries": 0, # disabled in favor of my own retries config.max_retries,
        }
        
        # Add optional parameters
        if config.max_tokens:
            params["max_tokens"] = config.max_tokens
        if config.api_key:
            params["api_key"] = config.api_key
        if config.api_base:
            params["azure_endpoint"] = config.api_base
        
        # Azure-specific parameters from extra_params
        azure_params = ["api_version", "azure_deployment", "azure_endpoint"]
        for param in azure_params:
            if param in config.extra_params:
                params[param] = config.extra_params[param]
        
        # Add remaining extra parameters
        for key, value in config.extra_params.items():
            if key not in azure_params:
                params[key] = value
        
        return AzureChatOpenAI(**params)
    
    def _create_google_llm(self, config: LLMConfig) -> BaseLanguageModel:
        """Create Google LLM instance"""
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ImportError:
            raise ImportError("langchain-google-genai is required for Google provider")
        
        # Build parameters
        params = {
            "model": config.model_name,
            "temperature": config.temperature,
            "timeout": config.timeout,
            "max_retries": 0, # disabled in favor of my own retries config.max_retries,
        }
        
        # Add optional parameters
        if config.max_tokens:
            params["max_output_tokens"] = config.max_tokens
        if config.api_key:
            params["google_api_key"] = config.api_key
        
        # Add extra parameters
        params.update(config.extra_params)
        
        return ChatGoogleGenerativeAI(**params)
    
    def _create_ollama_llm(self, config: LLMConfig) -> BaseLanguageModel:
        """Create Ollama LLM instance"""
        try:
            from langchain_ollama import ChatOllama
        except ImportError:
            raise ImportError("langchain-ollama is required for Ollama provider")
        
        # Build parameters
        params = {
            "model": config.model_name,
            "temperature": config.temperature,
            "timeout": config.timeout,
        }
        
        # Add optional parameters
        if config.api_base:
            params["base_url"] = config.api_base
        
        # Add extra parameters
        params.update(config.extra_params)
        
        return ChatOllama(**params)
    
    def _create_huggingface_llm(self, config: LLMConfig) -> BaseLanguageModel:
        """Create HuggingFace LLM instance"""
        try:
            from langchain_huggingface import ChatHuggingFace
        except ImportError:
            raise ImportError("langchain-huggingface is required for HuggingFace provider")
        
        # Build parameters
        params = {
            "model": config.model_name,
            "temperature": config.temperature,
        }
        
        # Add optional parameters
        if config.max_tokens:
            params["max_tokens"] = config.max_tokens
        if config.api_key:
            params["huggingfacehub_api_token"] = config.api_key
        if config.api_base:
            params["endpoint_url"] = config.api_base
        
        # Add extra parameters
        params.update(config.extra_params)
        
        return ChatHuggingFace(**params)
    
    def validate_config(self, config: LLMConfig) -> bool:
        """
        Validate LLM configuration
        
        Args:
            config: LLM configuration to validate
            
        Returns:
            True if configuration is valid
            
        Raises:
            ValueError: If configuration is invalid
        """
        # Check required fields
        if not config.provider:
            raise ValueError("Provider is required")
        if not config.model_name:
            raise ValueError("Model name is required")
        
        # Provider-specific validation
        if config.provider == LLMProvider.AZURE_OPENAI:
            required_azure_params = ["api_version"]
            for param in required_azure_params:
                if param not in config.extra_params:
                    raise ValueError(f"Azure OpenAI requires {param} in extra_params")
        
        return True
    
    def get_supported_providers(self) -> list[LLMProvider]:
        """Get list of supported providers"""
        return list(LLMProvider)
    
    def is_provider_available(self, provider: LLMProvider) -> bool:
        """
        Check if a provider is available (dependencies installed)
        
        Args:
            provider: Provider to check
            
        Returns:
            True if provider dependencies are available
        """
        try:
            if provider == LLMProvider.OPENAI:
                import langchain_openai
            elif provider == LLMProvider.ANTHROPIC:
                import langchain_anthropic
            elif provider == LLMProvider.AZURE_OPENAI:
                import langchain_openai
            elif provider == LLMProvider.GOOGLE:
                import langchain_google_genai
            elif provider == LLMProvider.OLLAMA:
                import langchain_ollama
            elif provider == LLMProvider.HUGGINGFACE:
                import langchain_huggingface
            else:
                return False
            return True
        except ImportError:
            return False