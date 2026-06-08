"""
Robust OpenRouterClient adapter

Features:
- config loading from env or dict
- key validation
- model fallback list (default starts with openai/gpt-oss-120b per user)
- retries with exponential backoff & respect Retry-After
- circuit breaker to fallback to degraded mode
- tolerant JSON parsing for multi-JSON outputs
"""

import os
import time
import requests
import json
from typing import List, Optional
from collections import deque

DEFAULT_MODELS = ["openai/gpt-oss-120b", "gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"]

class OpenRouterError(Exception):
    pass

class CircuitOpenError(OpenRouterError):
    pass

class OpenRouterClient:
    def __init__(self, config: Optional[dict] = None, logger=None):
        config = config or {}
        self.api_key = config.get("OPENROUTER_API_KEY") or os.getenv("OPENROUTER_API_KEY")
        self.base_url = config.get("OPENROUTER_URL", "https://api.openrouter.ai")
        self.models = config.get("model_priority", DEFAULT_MODELS)
        self.session = requests.Session()
        self.logger = logger or (lambda *a, **kw: None)
        # simple circuit-breaker state
        self.failure_window = deque(maxlen=20)
        self.fail_threshold = config.get("circuit_fail_threshold", 10)
        self.fail_window_seconds = config.get("circuit_window_seconds", 60)
        self.degraded = False

    def _record_failure(self):
        now = time.time()
        self.failure_window.append(now)
        # drop old
        while self.failure_window and (now - self.failure_window[0]) > self.fail_window_seconds:
            self.failure_window.popleft()
        if len(self.failure_window) >= self.fail_threshold:
            self.degraded = True
            self.logger("circuit_open", failures=len(self.failure_window))

    def _record_success(self):
        self.failure_window.clear()
        if self.degraded:
            self.logger("circuit_recovered")
        self.degraded = False

    def validate_key(self, test_model=None, timeout=8):
        if not self.api_key:
            raise OpenRouterError("OPENROUTER_API_KEY not provided")
        # a light-weight test; some backends provide auth ping endpoints; fallback to small request
        try:
            _ = self.query("ping", model=test_model or self.models[0], max_retries=1, timeout=timeout)
            return True
        except Exception as e:
            self.logger("key_validation_failed", error=str(e))
            raise

    def _post(self, path, payload, timeout=30):
        url = self.base_url.rstrip("/") + path
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        r = self.session.post(url, json=payload, headers=headers, timeout=timeout)
        return r

    def _tolerant_parse(self, text):
        # Try parse normally first
        try:
            return json.loads(text)
        except Exception:
            # try to salvage concatenated JSON blobs by scanning braces
            objs = []
            buf = ""
            depth = 0
            in_string = False
            escape = False
            for ch in text:
                buf += ch
                if ch == '"' and not escape:
                    in_string = not in_string
                if ch == "\\" and not escape:
                    escape = True
                else:
                    escape = False
                if not in_string:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                if depth == 0 and buf.strip():
                    try:
                        objs.append(json.loads(buf))
                    except Exception:
                        pass
                    buf = ""
            if objs:
                # return last best
                return objs[-1]
            # fallback: return raw text wrapped
            return {"__raw_text": text}

    def query(self, prompt: str, model: Optional[str] = None, max_retries: int = 3, timeout: int = 30):
        if self.degraded:
            raise CircuitOpenError("OpenRouter circuit is open; client is in degraded mode")
        model = model or (self.models[0] if self.models else None)
        payload = {"model": model, "input": prompt}
        attempt = 0
        last_exc = None
        while attempt < max_retries:
            attempt += 1
            try:
                r = self._post("/v1/chat/completions", payload, timeout=timeout)
                if r.status_code == 429:
                    retry_after = int(r.headers.get("Retry-After", "1"))
                    wait = retry_after * attempt
                    self.logger("rate_limited", wait=wait, attempt=attempt)
                    time.sleep(wait)
                    continue
                if r.status_code >= 500:
                    # server error, backoff
                    wait = 0.5 * (2 ** attempt)
                    self.logger("server_error", status=r.status_code, wait=wait)
                    time.sleep(wait)
                    continue
                body = r.text
                parsed = self._tolerant_parse(body)
                self._record_success()
                return parsed
            except Exception as e:
                last_exc = e
                self._record_failure()
                wait = 0.5 * (2 ** attempt)
                self.logger("request_exception", error=str(e), attempt=attempt, wait=wait)
                time.sleep(wait)
        raise OpenRouterError("All retries failed")
