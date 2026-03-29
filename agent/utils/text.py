"""
Shared text utilities for First Light.
"""


def split_message(text: str, chunk_size: int) -> list[str]:
    """Split text into chunks of at most chunk_size chars, breaking on newlines.

    Used by notification channels and bot message senders to stay within
    platform message length limits (Telegram: 4000, Slack: 2800).
    """
    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    while text:
        if len(text) <= chunk_size:
            chunks.append(text)
            break
        split_at = text.rfind("\n", 0, chunk_size)
        if split_at == -1:
            split_at = chunk_size
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks
