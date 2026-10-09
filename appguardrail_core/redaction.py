"""Shared redaction primitives for untrusted security evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

SENSITIVE_TEXT_PATTERNS = (
    re.compile(
        r"(?im)(['\"]?authorization['\"]?\s*[:=]\s*)"
        r"(?:'''(?:\\[\s\S]|(?!''')[\s\S])*(?:'''|\Z)|"
        r'"""(?:\\[\s\S]|(?!""")[\s\S])*(?:"""|\Z)|'
        r"`(?:\\[\s\S]|[^`\\])*(?:`|\Z)|"
        r"'(?:\\[\s\S]|[^'\\])*(?:'|\Z)|"
        r'"(?:\\[\s\S]|[^"\\])*(?:"|\Z)|'
        r"[^\r\n]+)"
    ),
    re.compile(
        r"(?im)\b(((?:[a-z][a-z0-9]*[_-])*(?:api[_-]?key|access[_-]?key|"
        r"access[_-]?key[_-]?id|secret[_-]?access[_-]?key(?:[_-]?id)?|"
        r"client[_-]?secret|access[_-]?token|"
        r"refresh[_-]?token|token|secret|password|private[_-]?key|credential)"
        r")\s*[:=]\s*)"
        r"(?:'''(?:\\[\s\S]|(?!''')[\s\S])*(?:'''|\Z)|"
        r'"""(?:\\[\s\S]|(?!""")[\s\S])*(?:"""|\Z)|'
        r"`(?:\\[\s\S]|[^`\\])*(?:`|\Z)|"
        r"'(?:\\[\s\S]|[^'\\])*(?:'|\Z)|"
        r'"(?:\\[\s\S]|[^"\\])*(?:"|\Z)|'
        r"[^'\"\s]+['\"]?)"
    ),
    re.compile(
        r"\b(?:"
        r"gh[opsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|"
        r"sk-[A-Za-z0-9]{20,}|sk-(?:ant|proj|svcacct)-[A-Za-z0-9_-]{20,}|"
        r"sk_(?:live|test)_[A-Za-z0-9]{12,}|"
        r"(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,}|"
        r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|"
        r"npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}"
        r")\b"
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
)
_SENSITIVE_FIELD_PARTS = frozenset(
    {
        "api_key",
        "authorization",
        "credential",
        "password",
        "private_key",
        "raw_evidence",
        "raw_output",
        "raw_payload",
        "raw_response",
        "raw",
        "request_body",
        "response_body",
        "secret",
        "source_code",
        "snippet",
        "findings",
        "token",
    }
)


def redact_sensitive_text(text: str) -> str:
    """Replace obvious credential material while preserving surrounding evidence."""
    for pattern in SENSITIVE_TEXT_PATTERNS:
        text = pattern.sub(
            lambda match: (
                f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]"
            ),
            text,
        )
    return text


def redact_sensitive_prefix(text: str, *, visible_length: int) -> str:
    """Redact a source-aligned prefix while using bounded suffix lookahead."""
    visible_length = max(0, min(visible_length, len(text)))
    secret_spans: list[tuple[int, int]] = []
    for pattern in SENSITIVE_TEXT_PATTERNS:
        for match in pattern.finditer(text):
            secret_start = match.end(1) if match.lastindex else match.start()
            secret_end = match.end()
            if secret_start < visible_length and secret_end > secret_start:
                secret_spans.append(
                    (secret_start, min(secret_end, visible_length))
                )
    if not secret_spans:
        return text[:visible_length]

    merged_spans: list[tuple[int, int]] = []
    for span_start, span_end in sorted(secret_spans):
        if merged_spans and span_start <= merged_spans[-1][1]:
            prior_start, prior_end = merged_spans[-1]
            merged_spans[-1] = (prior_start, max(prior_end, span_end))
        else:
            merged_spans.append((span_start, span_end))

    chunks: list[str] = []
    cursor = 0
    for span_start, span_end in merged_spans:
        chunks.extend((text[cursor:span_start], "[REDACTED]"))
        cursor = span_end
    chunks.append(text[cursor:visible_length])
    return "".join(chunks)


def redact_sensitive_value(value: Any, *, field_name: str = "") -> Any:
    """Recursively redact secret-bearing fields and text in finding extensions."""
    separated_name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", field_name)
    normalized_name = re.sub(
        r"[^a-z0-9]+", "_", separated_name.casefold()
    ).strip("_")
    name_parts = (
        frozenset(normalized_name.split("_")) if normalized_name else frozenset()
    )
    compound_name = normalized_name.replace("_", "")
    sensitive_name = bool(
        name_parts.intersection(
            {
                "authorization",
                "credential",
                "credentials",
                "findings",
                "password",
                "passwords",
                "raw",
                "secret",
                "secrets",
                "snippet",
                "snippets",
                "token",
                "tokens",
            }
        )
        or normalized_name in _SENSITIVE_FIELD_PARTS
        or {"api", "key"}.issubset(name_parts)
        or {"access", "key"}.issubset(name_parts)
        or {"private", "key"}.issubset(name_parts)
        or {"api", "keys"}.issubset(name_parts)
        or {"access", "keys"}.issubset(name_parts)
        or {"private", "keys"}.issubset(name_parts)
        or compound_name
        in {
            "apikey",
            "apikeys",
            "credentialdata",
            "privatekey",
            "privatekeys",
            "rawevidence",
            "rawoutput",
            "rawpayload",
            "rawresponse",
        }
    )
    if sensitive_name:
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, Mapping):
        sanitized: dict[Any, Any] = {}
        for key, child in value.items():
            safe_key = redact_sensitive_text(key) if isinstance(key, str) else key
            if safe_key in sanitized:
                base_key = safe_key if isinstance(safe_key, str) else repr(safe_key)
                suffix = 2
                while f"{base_key}#{suffix}" in sanitized:
                    suffix += 1
                safe_key = f"{base_key}#{suffix}"
            sanitized[safe_key] = redact_sensitive_value(
                child,
                field_name=key if isinstance(key, str) else "",
            )
        return sanitized
    if isinstance(value, tuple):
        return tuple(redact_sensitive_value(child) for child in value)
    if isinstance(value, list):
        return [redact_sensitive_value(child) for child in value]
    return value
