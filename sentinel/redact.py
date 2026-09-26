"""Strip secrets from text before it is sent to any cloud AI provider. Created by LalithPrabu."""

from __future__ import annotations

import re

_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bxox[bpas]-[A-Za-z0-9\-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "[REDACTED_GROQ_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\s*[=:]\s*)"
                r"(\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:)[^\s@/]+@"), r"\1[REDACTED]@"),
)


def redact(text: str) -> tuple[str, int]:
    """Return (redacted_text, number_of_secrets_replaced)."""
    total = 0
    for pattern, repl in _PATTERNS:
        text, n = pattern.subn(repl, text)
        total += n
    return text, total
