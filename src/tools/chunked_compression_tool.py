import logging
from typing import List, Dict, Any, Optional
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage

from ..core.token_manager import TokenCounter
from ..prompts.compression_system_prompt import COMPRESSION_SYSTEM_PROMPT

logger = logging.getLogger(__name__)
token_counter = TokenCounter()


def _split_messages_by_tokens(
    messages: List[BaseMessage], chunk_token_limit: int, model_name: str
) -> List[List[BaseMessage]]:
    """
    Splits messages into chunks, each not exceeding chunk_token_limit tokens.
    """
    chunks = []
    current_chunk = []
    current_tokens = 0

    for msg in messages:
        msg_tokens = token_counter.count_tokens(getattr(msg, "content", ""), model_name)
        # If adding this message would exceed the limit, start a new chunk
        if current_tokens + msg_tokens > chunk_token_limit and current_chunk:
            chunks.append(current_chunk)
            current_chunk = []
            current_tokens = 0
        current_chunk.append(msg)
        current_tokens += msg_tokens

    if current_chunk:
        chunks.append(current_chunk)
    return chunks


async def _summarize_chunk(llm, chunk: List[BaseMessage]) -> str:
    """
    Summarizes a chunk of messages using the LLM and the structured compression prompt.
    """
    messages_text = "\n\n".join(
        [f"**{type(msg).__name__}**: {getattr(msg, 'content', '')}" for msg in chunk]
    )
    prompt = f"{COMPRESSION_SYSTEM_PROMPT}\n\n{messages_text}"
    compression_messages = [
        SystemMessage(content=COMPRESSION_SYSTEM_PROMPT),
        HumanMessage(content=messages_text),
    ]
    # Call the LLM (assume llm.ainvoke is available)
    response = await llm.ainvoke(compression_messages)
    return getattr(response, "content", str(response))


async def _recursive_compress(
    llm,
    messages: List[BaseMessage],
    chunk_token_limit: int,
    final_token_limit: int,
    model_name: str,
) -> str:
    """
    Recursively compresses messages until the result fits within final_token_limit.
    """
    # Split into chunks (excluding system messages)
    system_messages = [msg for msg in messages if isinstance(msg, SystemMessage)]
    other_messages = [msg for msg in messages if not isinstance(msg, SystemMessage)]

    chunks = _split_messages_by_tokens(other_messages, chunk_token_limit, model_name)
    summaries = []
    for chunk in chunks:
        summary = await _summarize_chunk(llm, chunk)
        summaries.append(summary)

    # Combine summaries with system messages at the start
    combined = "\n\n".join(summaries)
    total_tokens = token_counter.count_tokens(combined, model_name)
    if total_tokens > final_token_limit and len(summaries) > 1:
        # Recursively compress the summaries
        summary_msgs = [HumanMessage(content=s) for s in summaries]
        return await _recursive_compress(
            llm, summary_msgs, chunk_token_limit, final_token_limit, model_name
        )
    else:
        # Prepend system messages if any
        sys_content = "\n\n".join(
            [getattr(msg, "content", "") for msg in system_messages]
        )
        if sys_content:
            return f"{sys_content}\n\n{combined}"
        else:
            return combined


async def compress_messages_chunked(
    messages: List[Dict[str, Any]],
    chunk_token_limit: int = 2048,
    final_token_limit: int = 4096,
    model_name: str = "gpt-4o-mini",
    llm: Optional[Any] = None,
) -> str:
    """
    Compresses a large array of messages into a concise, structured summary using chunked, recursive summarization.
    - messages: List of dicts representing the conversation (should be convertible to BaseMessage).
    - chunk_token_limit: Max tokens per chunk for the compression LLM.
    - final_token_limit: Target token limit for the final summary.
    - model_name: Which model to use for token counting.
    - llm: The LLM instance to use for summarization (must support ainvoke).
    Returns: A single string summary (structured as per the system prompt).
    """
    if llm is None:
        raise ValueError("You must provide an LLM instance with an 'ainvoke' method.")

    # Convert dicts to BaseMessage if needed
    base_messages = []
    for msg in messages:
        if isinstance(msg, BaseMessage):
            base_messages.append(msg)
        elif isinstance(msg, dict):
            # Try to reconstruct message type
            msg_type = msg.get("type", "human").lower()
            content = msg.get("content", "")
            if msg_type == "system":
                base_messages.append(SystemMessage(content=content))
            elif msg_type == "ai":
                base_messages.append(AIMessage(content=content))
            else:
                base_messages.append(HumanMessage(content=content))
        else:
            raise ValueError("Each message must be a dict or BaseMessage.")

    summary = await _recursive_compress(
        llm, base_messages, chunk_token_limit, final_token_limit, model_name
    )
    return summary
