from __future__ import annotations

from types import SimpleNamespace

import pytest

from sentinel import cli
from sentinel.delivery.telegram_bot import extract_chat_candidates, format_chat_candidates


def test_extract_chat_candidates_prefers_unique_channel_and_message_chats() -> None:
    channel_chat = SimpleNamespace(id=-1001234567890, type="channel", title="SENTINEL IOC JOBS", username=None)
    direct_chat = SimpleNamespace(id=424242, type="private", title=None, username="nichoalas")
    channel_update = SimpleNamespace(
        effective_chat=channel_chat,
        channel_post=object(),
        edited_channel_post=None,
        message=None,
        edited_message=None,
        my_chat_member=None,
        chat_member=None,
    )
    duplicate_channel_update = SimpleNamespace(
        effective_chat=channel_chat,
        channel_post=None,
        edited_channel_post=object(),
        message=None,
        edited_message=None,
        my_chat_member=None,
        chat_member=None,
    )
    direct_message_update = SimpleNamespace(
        effective_chat=direct_chat,
        channel_post=None,
        edited_channel_post=None,
        message=object(),
        edited_message=None,
        my_chat_member=None,
        chat_member=None,
    )

    candidates = extract_chat_candidates([channel_update, duplicate_channel_update, direct_message_update])

    assert [candidate.chat_id for candidate in candidates] == ["-1001234567890", "424242"]
    assert candidates[0].chat_type == "channel"
    assert candidates[0].title == "SENTINEL IOC JOBS"
    assert candidates[0].update_type == "channel_post"
    assert candidates[1].username == "nichoalas"


def test_format_chat_candidates_includes_operator_hint_when_empty() -> None:
    rendered = format_chat_candidates([])

    assert "No Telegram updates found." in rendered
    assert "run this command again" in rendered


@pytest.mark.asyncio
async def test_cli_dispatch_prints_discovered_chat_ids(monkeypatch, capsys) -> None:
    settings = SimpleNamespace(
        delivery=SimpleNamespace(
            telegram_token="token",
        )
    )

    async def fake_fetch_chat_candidates(token: str, *, limit: int = 20):
        assert token == "token"
        assert limit == 5
        return [
            SimpleNamespace(
                chat_id="-1001234567890",
                chat_type="channel",
                title="SENTINEL IOC JOBS",
                username=None,
                update_type="channel_post",
            )
        ]

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "fetch_chat_candidates", fake_fetch_chat_candidates)

    await cli._dispatch("telegram-chat-id", limit=5)

    output = capsys.readouterr().out
    assert "-1001234567890" in output
    assert "SENTINEL IOC JOBS" in output
