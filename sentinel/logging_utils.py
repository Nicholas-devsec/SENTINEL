from __future__ import annotations

import logging
import re


_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
_HTTP_LOGGER_NAMES = ("httpx", "httpcore", "telegram", "telegram.ext")
_REDACTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"https://api\.telegram\.org/bot(?P<token>[^/\s]+)/"),
        "https://api.telegram.org/bot<redacted>/",
    ),
    (
        re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b"),
        "<redacted-telegram-token>",
    ),
    (
        re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
        "<redacted-openai-key>",
    ),
    (
        re.compile(r"(?i)\b(authorization)\b([=:]\s*|\s+)(bearer\s+)([A-Za-z0-9._\-]+)"),
        r"\1\2\3<redacted>",
    ),
    (
        re.compile(r"(?i)\b(api[_ -]?key|token|secret)\b([=:]\s*)([^\s,;]+)"),
        r"\1\2<redacted>",
    ),
)


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern, replacement in _REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact_secrets(super().format(record))


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, format=_LOG_FORMAT)
    formatter = RedactingFormatter(_LOG_FORMAT)
    root = logging.getLogger()
    for handler in root.handlers:
        handler.setFormatter(formatter)
    for logger_name in _HTTP_LOGGER_NAMES:
        logging.getLogger(logger_name).setLevel(logging.WARNING)
