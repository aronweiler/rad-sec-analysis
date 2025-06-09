# src/core/context_window_manager.py

import logging
from typing import List, Optional, Tuple, Dict, Any
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage
from langchain_core.language_models import BaseLanguageModel

from ..core.token_manager import TokenCounter
from ..core.llm_factory import LLMFactory
from ..models.stage_config import CompressionConfig, CompressionStrategy
from ..models.llm_config import LLMConfig
from ..prompts.compression_system_prompt import COMPRESSION_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

class CompressionError(Exception):
    """Error during context compression"""
    pass

class ContextWindowManager:
    """Manages context window size through intelligent compression"""

    def __init__(self, token_counter: TokenCounter, llm_factory: LLMFactory):
        self.token_counter = token_counter
        self.llm_factory = llm_factory
        self.logger = logging.getLogger(__name__)

    async def manage_context_window(
        self,
        messages: List[BaseMessage],
        compression_config: CompressionConfig,
        model_name: str = "default",
        available_tools: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[BaseMessage], bool]:
        """
        Manage context window size, compressing if necessary

        Args:
            messages: Current conversation messages
            compression_config: Compression configuration
            model_name: Model name for token counting
            available_tools: Available tools for compression

        Returns:
            Tuple of (processed_messages, was_compressed)
        """
        if not compression_config.enabled:
            return messages, False

        # Count current tokens
        current_tokens = self._count_message_tokens(messages, model_name)

        if current_tokens <= compression_config.token_threshold:
            self.logger.debug(f"Context size ({current_tokens} tokens) below threshold ({compression_config.token_threshold})")
            return messages, False

        self.logger.info(f"Context size ({current_tokens} tokens) exceeds threshold ({compression_config.token_threshold}), compressing...")

        try:
            # Attempt primary compression strategy
            if compression_config.compression_tool and available_tools:
                compressed_messages = await self._compress_with_tool(
                    messages, compression_config, available_tools
                )
            else:
                compressed_messages = await self._compress_with_prompt(
                    messages, compression_config
                )

            # Verify compression was effective
            compressed_tokens = self._count_message_tokens(compressed_messages, model_name)
            self.logger.info(f"Compression successful: {current_tokens} -> {compressed_tokens} tokens")

            return compressed_messages, True

        except Exception as e:
            self.logger.warning(f"Primary compression failed: {e}, falling back...")
            return await self._apply_fallback_compression(messages, compression_config)

    async def _compress_with_tool(
        self,
        messages: List[BaseMessage],
        compression_config: CompressionConfig,
        available_tools: Dict[str, Any]
    ) -> List[BaseMessage]:
        """Compress using configured compression tool"""

        # Get compression LLM
        compression_llm = self._get_compression_llm(compression_config)

        # Get compression tool
        compression_tool = available_tools.get(compression_config.compression_tool)
        if not compression_tool:
            raise CompressionError(f"Compression tool '{compression_config.compression_tool}' not available")

        # Bind tool to LLM
        llm_with_tool = compression_llm.bind_tools([compression_tool])

        # Separate system messages from others
        system_messages, other_messages = self._separate_system_messages(messages)

        # Create compression prompt
        compression_prompt = self._create_tool_compression_prompt(other_messages)
        compression_messages = [
            SystemMessage(content="You are a context compression specialist. You MUST use the provided compression tool to compress the conversation history."),
            HumanMessage(content=compression_prompt)
        ]

        # Execute compression with retries for validation errors
        for attempt in range(compression_config.max_compression_retries + 1):
            try:
                response = await llm_with_tool.ainvoke(compression_messages)

                if not response.tool_calls:
                    if attempt < compression_config.max_compression_retries:
                        retry_msg = HumanMessage(content=f"You must use the {compression_config.compression_tool} tool to compress the context. Please call the tool with the conversation messages.")
                        compression_messages.append(response)
                        compression_messages.append(retry_msg)
                        continue
                    else:
                        raise CompressionError("Compression tool was not called after maximum retries")

                # Execute the tool (simplified - should make tool manager more generic to handle this as well)
                tool_call = response.tool_calls[0]
                tool_args = tool_call["args"]

                # Tool should return compressed content
                if compression_tool.coroutine:
                    compressed_content = await compression_tool.ainvoke(tool_args)
                else:
                    compressed_content = compression_tool.invoke(tool_args)

                # Create compressed message
                compressed_message = HumanMessage(content=str(compressed_content))

                # Return system messages + compressed message
                return system_messages + [compressed_message]

            except Exception as e:
                if attempt < compression_config.max_compression_retries:
                    self.logger.warning(f"Compression attempt {attempt + 1} failed: {e}, retrying...")
                    retry_msg = HumanMessage(content=f"There was an error with your compression: {e}. Please try again using the {compression_config.compression_tool} tool.")
                    compression_messages.append(response if 'response' in locals() else AIMessage(content="Error occurred"))
                    compression_messages.append(retry_msg)
                    continue
                else:
                    raise CompressionError(f"Tool compression failed after {compression_config.max_compression_retries} retries: {e}")

        raise CompressionError("Unexpected end of compression retry loop")

    async def _compress_with_prompt(
        self,
        messages: List[BaseMessage],
        compression_config: CompressionConfig,
    ) -> List[BaseMessage]:
        """Compress using intelligent prompt-based compression"""

        # Get compression LLM
        compression_llm = self._get_compression_llm(compression_config)

        # Separate system messages from others
        system_messages, other_messages = self._separate_system_messages(messages)

        # Create compression prompt
        compression_prompt = self._create_prompt_compression_request(other_messages)
        compression_messages = [
            SystemMessage(content=COMPRESSION_SYSTEM_PROMPT),
            HumanMessage(content=compression_prompt)
        ]

        # Execute compression
        response = await compression_llm.ainvoke(compression_messages)

        # Create compressed message
        compressed_message = HumanMessage(content=response.content)

        # Return system messages + compressed message
        return system_messages + [compressed_message]

    async def _apply_fallback_compression(
        self,
        messages: List[BaseMessage],
        compression_config: CompressionConfig,
    ) -> Tuple[List[BaseMessage], bool]:
        """Apply fallback compression strategy"""

        if compression_config.fallback_strategy == CompressionStrategy.INTELLIGENT_PROMPT:
            try:
                compressed_messages = await self._compress_with_prompt(messages, compression_config)
                return compressed_messages, True
            except Exception as e:
                self.logger.warning(f"Fallback prompt compression failed: {e}, using simple truncation")

        # Simple truncation fallback
        system_messages, other_messages = self._separate_system_messages(messages)

        # Keep last N messages
        preserved_messages = other_messages[-compression_config.preserve_last_n_messages:]

        final_messages = system_messages + preserved_messages
        self.logger.info(f"Applied simple truncation: kept {len(final_messages)} messages")

        return final_messages, True

    def _get_compression_llm(self, compression_config: CompressionConfig) -> BaseLanguageModel:
        """Get LLM for compression (uses compression config or falls back to default)"""
        if compression_config.compression_llm_config:
            return self.llm_factory.create_llm(compression_config.compression_llm_config)
        else:
            # Would need access to stage LLM - this is a simplified version
            # We could fall back and pass stage LLM or config here, but just error for now
            raise CompressionError("No compression LLM configured and no fallback provided")

    def _separate_system_messages(self, messages: List[BaseMessage]) -> Tuple[List[BaseMessage], List[BaseMessage]]:
        """Separate system messages from other messages"""
        system_messages = [msg for msg in messages if isinstance(msg, SystemMessage)]
        other_messages = [msg for msg in messages if not isinstance(msg, SystemMessage)]
        return system_messages, other_messages

    def _count_message_tokens(self, messages: List[BaseMessage], model_name: str) -> int:
        """Count tokens in message list"""
        total_tokens = 0
        for message in messages:
            content = getattr(message, 'content', '')
            total_tokens += self.token_counter.count_tokens(str(content), model_name)
        return total_tokens

    def _create_tool_compression_prompt(self, messages: List[BaseMessage]) -> str:
        """Create prompt for tool-based compression"""
        messages_text = "\n\n".join([
            f"**{type(msg).__name__}**: {getattr(msg, 'content', '')}"
            for msg in messages
        ])

        return f"""Please compress the following conversation messages while preserving all critical information:

{messages_text}

Use the compression tool to provide a comprehensive but concise summary that maintains all essential context for continuing the current task."""

    def _create_prompt_compression_request(self, messages: List[BaseMessage]) -> str:
        """Create prompt for prompt-based compression"""
        messages_text = "\n\n".join([
            f"**{type(msg).__name__}**: {getattr(msg, 'content', '')}"
            for msg in messages
        ])

        return f"""Please compress the following conversation messages:

{messages_text}

Provide a comprehensive but concise summary that preserves all critical information needed to continue the current task."""