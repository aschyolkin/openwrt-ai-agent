from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit


SECRET_KEY = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|uuid|short[_-]?id|credential|authorization|cookie|subscription.*url)", re.I)
UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}")
ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*[^\s,;]+")
VLESS = re.compile(r"(?i)vless://[^\s]+")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
DOMAIN = re.compile(r"(?<![@\w.-])(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}(?![\w.-])")


def redact_text(text: str) -> str:
    text = BEARER.sub(r"\1***redacted***", text)
    text = ASSIGNMENT.sub(lambda m: f"{m.group(1)}=***redacted***", text)
    text = UUID.sub("***redacted-uuid***", text)
    text = VLESS.sub("vless://***redacted***", text)
    return text


def redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "***redacted***"
    if not parsed.scheme or not parsed.netloc:
        return "***redacted***"
    host = parsed.hostname or "redacted.invalid"
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit((parsed.scheme, host + port, parsed.path, "***redacted***" if parsed.query else "", ""))


def sanitize(value: Any) -> Any:
    """Recursively remove known credential-bearing keys and token shapes."""
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if SECRET_KEY.search(str(key)):
                result[str(key)] = "***redacted***"
            else:
                result[str(key)] = sanitize(item)
        return result
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_log_network_data(text: str, allow_ips: set[str] | None = None, allow_domains: set[str] | None = None) -> str:
    allow_ips = allow_ips or {"127.0.0.1", "10.110.112.1", "0.0.0.0"}
    allow_domains = allow_domains or {"localhost"}
    text = redact_text(text)
    text = IPV4.sub(lambda m: m.group(0) if m.group(0) in allow_ips else "***redacted-ip***", text)
    text = DOMAIN.sub(lambda m: m.group(0) if m.group(0).lower() in allow_domains else "***redacted-domain***", text)
    return text

