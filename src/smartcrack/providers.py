"""LLM provider registry — maps provider names to base URLs and default models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderInfo:
    """Known LLM provider configuration."""

    name: str
    base_url: str
    default_model: str
    models: tuple[str, ...]


PROVIDERS: dict[str, ProviderInfo] = {
    "gemini": ProviderInfo(
        name="Google Gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        default_model="gemini-2.5-flash",
        models=(
            "gemini-2.5-flash",
            "gemini-2.5-pro",
            "gemini-2.5-flash-lite",
            "gemini-2.0-flash",
        ),
    ),
    "openai": ProviderInfo(
        name="OpenAI",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        models=(
            "gpt-4o-mini",
            "gpt-4o",
            "gpt-4.1-mini",
            "gpt-4.1-nano",
        ),
    ),
    "groq": ProviderInfo(
        name="Groq",
        base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",
        models=(
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "gemma2-9b-it",
        ),
    ),
    "together": ProviderInfo(
        name="Together AI",
        base_url="https://api.together.xyz/v1",
        default_model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
        models=(
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
        ),
    ),
    "openrouter": ProviderInfo(
        name="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        default_model="google/gemini-2.5-flash",
        models=(
            "google/gemini-2.5-flash",
            "google/gemini-2.5-pro",
            "anthropic/claude-sonnet-4",
            "meta-llama/llama-3.3-70b-instruct",
        ),
    ),
}

PROVIDER_NAMES = tuple(PROVIDERS.keys())


def resolve_provider(
    provider: str | None,
    api_key: str,
    base_url: str,
    model: str,
) -> tuple[str, str, str]:
    """Resolve provider shorthand to (base_url, api_key, model).

    Priority:
    1. Explicit --llm-base-url overrides everything
    2. --provider name resolves to known base_url + default model
    3. Auto-detect from API key prefix (AIza* = gemini, sk-* = openai)

    Returns:
        (base_url, api_key, model) tuple ready for LLMConfig.
    """
    # Explicit base URL takes priority
    if base_url:
        return base_url, api_key, model

    # Named provider
    if provider and provider.lower() in PROVIDERS:
        info = PROVIDERS[provider.lower()]
        resolved_model = model or info.default_model
        return info.base_url, api_key, resolved_model

    # Auto-detect from key prefix
    if api_key.startswith("AIza"):
        info = PROVIDERS["gemini"]
        return info.base_url, api_key, model or info.default_model

    if api_key.startswith("sk-"):
        info = PROVIDERS["openai"]
        return info.base_url, api_key, model or info.default_model

    if api_key.startswith("gsk_"):
        info = PROVIDERS["groq"]
        return info.base_url, api_key, model or info.default_model

    return base_url, api_key, model
