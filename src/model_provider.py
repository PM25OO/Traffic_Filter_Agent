"""Model provider factory for chat models."""

from __future__ import annotations

import os
from typing import Optional

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI


def create_chat_model(
    provider: str,
    model_name: str,
    temperature: float,
    base_url: Optional[str] = None,
) -> BaseChatModel:
    provider = provider.strip().lower()

    if provider == "deepseek":
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            raise RuntimeError("DEEPSEEK_API_KEY is required for DeepSeek provider.")
        resolved_base = base_url or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key,
            base_url=resolved_base,
            # Disable thinking mode to avoid reasoning_content round-trip errors.
            extra_body={"thinking": {"type": "disabled"}},
        )

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required for OpenAI provider.")
        resolved_base = base_url or os.getenv("OPENAI_BASE_URL")
        if resolved_base:
            return ChatOpenAI(
                model=model_name,
                temperature=temperature,
                api_key=api_key,
                base_url=resolved_base,
            )
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key,
        )

    raise ValueError(f"Unsupported provider: {provider}")
