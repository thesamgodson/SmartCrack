"""Configuration loading from environment variables."""

from __future__ import annotations

import logging
import os

from hashcrack.models import LLMConfig

logger = logging.getLogger(__name__)


def load_llm_config() -> LLMConfig:
    """Load LLM configuration from environment variables or defaults."""
    try:
        timeout = int(os.environ.get("HASHCRACK_LLM_TIMEOUT", "90"))
    except ValueError:
        timeout = 90
        logger.warning("HASHCRACK_LLM_TIMEOUT is not a valid integer; defaulting to 90s")

    return LLMConfig(
        base_url=os.environ.get("HASHCRACK_LLM_BASE_URL", ""),
        api_key=os.environ.get("HASHCRACK_LLM_API_KEY", ""),
        model=os.environ.get("HASHCRACK_LLM_MODEL", ""),
        timeout_seconds=timeout,
    )
