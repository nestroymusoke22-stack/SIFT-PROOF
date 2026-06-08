import os
import json
import re
import time


def get_backend():
    return os.getenv("AI_BACKEND", "groq").lower()


def chat(messages, system_prompt=None):
    """
    Sends messages to the LLM and returns raw text response.
    No tool calling API used — model outputs JSON we parse ourselves.
    """
    backend = get_backend()

    if backend == "groq":
        return _groq(messages, system_prompt)
    elif backend == "ollama":
        return _ollama(messages, system_prompt)
    elif backend == "anthropic":
        return _anthropic(messages, system_prompt)
    elif backend == "openrouter":
        return _openrouter(messages, system_prompt)
    else:
        raise ValueError(f"Unknown backend: {backend}")


def _groq(messages, system_prompt):
    from groq import Groq

    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise ValueError("GROQ_API_KEY not set. Get free key at console.groq.com")

    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    client = Groq(api_key=key)

    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    # Retry with exponential backoff on transient rate-limit / size errors
    max_retries = int(os.getenv("GROQ_MAX_RETRIES", "5"))
    delay = 2.0
    last_err = None
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=full_messages,
                temperature=0.1,
                max_tokens=2048
            )
            return response.choices[0].message.content
        except Exception as e:
            last_err = e
            status = getattr(e, "status_code", None) or getattr(
                getattr(e, "response", None), "status_code", None)
            retryable = status in (429, 413, 500, 502, 503) or status is None
            if not retryable or attempt == max_retries - 1:
                raise
            wait = getattr(e, "retry_after", None)
            try:
                wait = float(wait) if wait else delay
            except (TypeError, ValueError):
                wait = delay
            print(f"[GROQ] transient error (status={status}); "
                  f"retry {attempt + 1}/{max_retries} in {wait:.1f}s")
            time.sleep(wait)
            delay = min(delay * 2, 30)
    raise last_err


def _openrouter(messages, system_prompt):
    from openai import OpenAI

    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        raise ValueError("OPENROUTER_API_KEY not set. Get a free key at openrouter.ai")

    # Defaulting to OpenAI's massive high-reasoning flagship open variant
    model = os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b")
    
    # Reroute to OpenRouter gateway using native OpenAI SDK client specs
    client = OpenAI(
        api_key=key,
        base_url="https://openrouter.ai/api/v1"
    )

    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    max_retries = int(os.getenv("OPENROUTER_MAX_RETRIES", "5"))
    delay = 2.0
    last_err = None
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=full_messages,
                temperature=0.1,
                max_tokens=2048
            )
            return response.choices[0].message.content
        except Exception as e:
            last_err = e
            status = getattr(e, "status_code", None) or getattr(
                getattr(e, "response", None), "status_code", None)
            retryable = status in (429, 413, 500, 502, 503) or status is None
            if not retryable or attempt == max_retries - 1:
                raise
            print(f"[OPENROUTER] transient error (status={status}); "
                  f"retry {attempt + 1}/{max_retries} in {delay:.1f}s")
            time.sleep(delay)
            delay = min(delay * 2, 30)
    raise last_err


def _ollama(messages, system_prompt):
    import requests

    model = os.getenv("OLLAMA_MODEL", "mistral:7b")
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")

    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    resp = requests.post(
        f"{host}/v1/chat/completions",
        json={
            "model": model,
            "messages": full_messages,
            "stream": False,
            "temperature": 0.1
        },
        timeout=120
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _anthropic(messages, system_prompt):
    import anthropic

    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError("ANTHROPIC_API_KEY not set.")

    client = anthropic.Anthropic(api_key=key)
    model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    conv = [m for m in messages if m["role"] != "system"]

    response = client.messages.create(
        model=model,
        max_tokens=2048,
        system=system_prompt or "",
        messages=conv
    )
    return response.content[0].text


def parse_tool_call(text):
    if not text:
        return None

    patterns = [
        r'```json\s*(\{.*?\})\s*```',
        r'```\s*(\{.*?\})\s*```',
        r'(\{[^{}]*"tool"[^{}]*\})',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                if "tool" in data:
                    return data
            except json.JSONDecodeError:
                continue

    try:
        text_clean = text.strip()
        if text_clean.startswith("{"):
            data = json.loads(text_clean)
            if "tool" in data:
                return data
    except json.JSONDecodeError:
        pass

    return None


def get_backend_info():
    backend = get_backend()
    if backend == "groq":
        return {
            "backend": "Groq",
            "model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            "cost": "FREE",
            "key_set": bool(os.getenv("GROQ_API_KEY"))
        }
    elif backend == "ollama":
        return {
            "backend": "Ollama (local)",
            "model": os.getenv("OLLAMA_MODEL", "mistral:7b"),
            "cost": "FREE (offline)",
            "key_set": True
        }
    elif backend == "anthropic":
        return {
            "backend": "Anthropic Claude",
            "model": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            "cost": "PAID",
            "key_set": bool(os.getenv("ANTHROPIC_API_KEY"))
        }
    elif backend == "openrouter":
        return {
            "backend": "OpenRouter Gateway",
            "model": os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b"),
            "cost": "FREE-TIER",
            "key_set": bool(os.getenv("OPENROUTER_API_KEY"))
        }