from __future__ import annotations

from types import SimpleNamespace

import pytest

from sentinel.config import OpenAISettings
from sentinel.loops.providers.openai_provider import OpenAIProvider


class FakeResponsesAPI:
    def __init__(self, response) -> None:
        self.response = response
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class FakeOpenAIClient:
    def __init__(self, response) -> None:
        self.responses = FakeResponsesAPI(response)


@pytest.mark.asyncio
async def test_openai_provider_uses_output_text_when_available() -> None:
    response = SimpleNamespace(output_text='{"description":"ok"}')
    client = FakeOpenAIClient(response)
    provider = OpenAIProvider(
        OpenAISettings(api_key="test-key", model="gpt-5.4"),
        client=client,
    )

    result = await provider.complete("hello")

    assert result == '{"description":"ok"}'
    assert client.responses.calls[0]["model"] == "gpt-5.4"
    assert client.responses.calls[0]["input"] == "hello"


@pytest.mark.asyncio
async def test_openai_provider_falls_back_to_output_content_blocks() -> None:
    response = SimpleNamespace(
        output_text="",
        output=[
            SimpleNamespace(content=[SimpleNamespace(text='{"description":"'), SimpleNamespace(text='ok"}')])
        ],
    )
    provider = OpenAIProvider(
        OpenAISettings(api_key="test-key", model="gpt-5.4"),
        client=FakeOpenAIClient(response),
    )

    result = await provider.complete("prompt")

    assert result == '{"description":"ok"}'
