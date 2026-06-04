

import os
import json
import re


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

    response = client.chat.completions.create(
        model=model,
        messages=full_messages,
        temperature=0.1,
        max_tokens=2048
    )
    return response.choices[0].message.content


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
        json={"model": model, "messages": full_messages,
              "stream": False, "temperature": 0.1},
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
    """
    Parses the model's JSON response into a tool call dict.

    Model is instructed to output exactly one of:
      {"tool": "tool_name", "arguments": {...}}
      {"tool": "DONE", "arguments": {"summary": "..."}}

    Returns dict with keys: tool, arguments
    Returns None if no valid JSON found (treat as final message).
    """
    if not text:
        return None

    # Try to find JSON block in the response
    # Model sometimes wraps it in ```json ... ``` or just outputs raw JSON
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

    # Try parsing the whole response as JSON
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
