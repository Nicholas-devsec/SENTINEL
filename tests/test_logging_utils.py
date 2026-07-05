from __future__ import annotations

import logging

from sentinel.logging_utils import RedactingFormatter, configure_logging, redact_secrets


def test_redact_secrets_hides_telegram_bot_token_in_url() -> None:
    text = (
        'HTTP Request: POST '
        'https://api.telegram.org/bot8748231986:FAKE_TOKEN_FRAGMENT_FOR_REDACTION_TEST/sendMessage '
        '"HTTP/1.1 200 OK"'
    )

    redacted = redact_secrets(text)

    assert "8748231986:FAKE_TOKEN_FRAGMENT_FOR_REDACTION_TEST" not in redacted
    assert "https://api.telegram.org/bot<redacted>/sendMessage" in redacted


def test_redact_secrets_hides_common_api_key_patterns() -> None:
    text = "OPENAI api_key=sk-abc1234567890 token=super-secret Authorization: Bearer abc.def.ghi"

    redacted = redact_secrets(text)

    assert "sk-abc1234567890" not in redacted
    assert "super-secret" not in redacted
    assert "abc.def.ghi" not in redacted
    assert "api_key=<redacted>" in redacted
    assert "token=<redacted>" in redacted
    assert "Authorization: Bearer <redacted>" in redacted


def test_redacting_formatter_sanitizes_logged_message() -> None:
    formatter = RedactingFormatter("%(message)s")
    record = logging.LogRecord(
        name="httpx",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="POST https://api.telegram.org/bot8748231986:FAKE_TOKEN_FRAGMENT_FOR_REDACTION_TEST/sendMessage",
        args=(),
        exc_info=None,
    )

    rendered = formatter.format(record)

    assert "<redacted>" in rendered
    assert "FAKE_TOKEN_FRAGMENT_FOR_REDACTION_TEST" not in rendered


def test_configure_logging_turns_down_verbose_http_loggers(monkeypatch) -> None:
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: None)

    root = logging.getLogger()
    handler = logging.StreamHandler()
    original_handlers = list(root.handlers)
    root.handlers = [handler]
    try:
        configure_logging()
        assert isinstance(root.handlers[0].formatter, RedactingFormatter)
        assert logging.getLogger("httpx").level == logging.WARNING
        assert logging.getLogger("httpcore").level == logging.WARNING
        assert logging.getLogger("telegram").level == logging.WARNING
    finally:
        root.handlers = original_handlers
