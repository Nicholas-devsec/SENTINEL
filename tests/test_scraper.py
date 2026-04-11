from __future__ import annotations

import json

import fakeredis.aioredis
import httpx
import pytest

from sentinel.agents.scraper import (
    FeodoTrackerAdapter,
    OTXPulseAdapter,
    RSSAdapter,
    ScraperAgent,
    SourceScrapeDiagnostic,
    URLHausAdapter,
)
from sentinel.config import SentinelSettings


@pytest.fixture
def settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "sources": {
                "otx_api_key": "test-otx-key",
                "feeds": [
                    {"name": "urlhaus", "url": "https://feeds.local/urlhaus.csv", "trust": 0.1},
                    {"name": "feodotracker", "url": "https://feeds.local/feodo.json", "trust": 0.1},
                    {"name": "otx", "url": "https://feeds.local/otx", "trust": 0.1},
                    {"name": "rss_default", "url": "https://feeds.local/rss.xml", "trust": 0.1},
                ],
            },
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "redis://localhost:6379/0"},
        }
    )


@pytest.mark.asyncio
async def test_urlhaus_adapter_parses_csv() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            text="id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
            "1,2026-04-08 12:00:00,http://malicious.test,online,2026-04-08 12:05:00,malware_download,phishing,https://urlhaus.local/1,tester\n",
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = URLHausAdapter("https://feeds.local/urlhaus.csv", trust_score=0.91, client=client)
        records = await adapter.fetch()

    assert len(records) == 1
    assert records[0].value == "http://malicious.test"
    assert records[0].source == "urlhaus"
    assert records[0].source_trust == 0.91


@pytest.mark.asyncio
async def test_feodotracker_adapter_parses_json() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json=[
                {
                    "ip_address": "203.0.113.10",
                    "first_seen": "2026-04-08T12:00:00Z",
                    "last_online": "2026-04-08T13:00:00Z",
                    "malware": "trickbot",
                    "port": 443,
                }
            ],
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = FeodoTrackerAdapter("https://feeds.local/feodo.json", trust_score=0.93, client=client)
        records = await adapter.fetch()

    assert len(records) == 1
    assert records[0].value == "203.0.113.10"
    assert records[0].type == "ipv4"


@pytest.mark.asyncio
async def test_rss_adapter_parses_feed_entries() -> None:
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>SENTINEL Feed</title>
        <item>
          <title>Malware campaign update</title>
          <link>https://feeds.local/posts/1</link>
          <pubDate>Tue, 08 Apr 2026 12:00:00 GMT</pubDate>
          <description>New phishing infrastructure observed.</description>
        </item>
      </channel>
    </rss>"""
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=rss_xml))
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = RSSAdapter("https://feeds.local/rss.xml", trust_score=0.6, client=client)
        records = await adapter.fetch()

    assert len(records) == 1
    assert records[0].value == "https://feeds.local/posts/1"
    assert records[0].reference_url == "https://feeds.local/posts/1"


@pytest.mark.asyncio
async def test_otx_pulse_adapter_extracts_indicators() -> None:
    seen_params: dict[str, str] = {}

    transport = httpx.MockTransport(
        lambda request: (
            seen_params.update(dict(request.url.params)),
            httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "id": "pulse-123",
                            "name": "OTX Pulse Match",
                            "modified": "2026-04-08T12:00:00Z",
                            "tags": ["phishing"],
                            "references": ["https://otx.alienvault.com/pulse/123"],
                            "indicators": [
                                {
                                    "id": "indicator-123",
                                    "indicator": "https://otx.bad.test",
                                    "type": "URL",
                                    "created": "2026-04-08T12:00:00Z",
                                }
                            ],
                        }
                    ]
                },
            ),
        )[1]
    )
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = OTXPulseAdapter(
            "https://feeds.local/otx",
            trust_score=0.9,
            lookback_hours=24,
            api_key="test-key",
            client=client,
        )
        records = await adapter.fetch()

    assert len(records) == 1
    assert records[0].value == "https://otx.bad.test"
    assert records[0].reference_url == "https://otx.alienvault.com/pulse/123"
    assert records[0].attributes["pulse_id"] == "pulse-123"
    assert seen_params["limit"] == "50"
    assert "modified_since" in seen_params


@pytest.mark.asyncio
async def test_otx_pulse_adapter_normalizes_real_hash_indicator_types() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "results": [
                    {
                        "id": "pulse-hash",
                        "name": "Hash Pulse",
                        "modified": "2026-04-08T12:00:00Z",
                        "indicators": [
                            {"indicator": "5190ef1733183a0dc63fb623357f56d6", "type": "FileHash-MD5"},
                            {"indicator": "15efe7c0a510950c753a9ec1a388d699b341a2c4", "type": "FileHash-SHA1"},
                            {"indicator": "866993e9950250ac2ce8c3b4c6a8bd39285e0fafd93860f235a3b0370f160dd1", "type": "FileHash-SHA256"},
                        ],
                    }
                ]
            },
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = OTXPulseAdapter(
            "https://feeds.local/otx",
            trust_score=0.9,
            api_key="test-key",
            client=client,
        )
        records = await adapter.fetch()

    assert [record.type for record in records] == ["md5", "sha1", "sha256"]


@pytest.mark.asyncio
async def test_scraper_agent_filters_stale_items_and_extracts_related_cves(settings: SentinelSettings) -> None:
    settings.sources.max_item_age_hours = 24

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("urlhaus.csv"):
            return httpx.Response(
                200,
                text="id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n",
            )
        if request.url.path.endswith("feodo.json"):
            return httpx.Response(200, json=[])
        if request.url.path.endswith("otx"):
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "id": "recent-pulse",
                            "name": "Recent CVE Pulse",
                            "modified": "2026-04-08T11:00:00Z",
                            "references": ["https://otx.alienvault.com/pulse/recent"],
                            "tags": ["CVE-2026-12345"],
                            "indicators": [{"indicator": "example-recent.test", "type": "domain"}],
                        },
                        {
                            "id": "old-pulse",
                            "name": "Old Pulse",
                            "modified": "2026-04-01T00:00:00Z",
                            "indicators": [{"indicator": "example-old.test", "type": "domain"}],
                        },
                    ]
                },
            )
        if request.url.path.endswith("rss.xml"):
            return httpx.Response(200, text="<?xml version='1.0'?><rss version='2.0'><channel></channel></rss>")
        raise AssertionError(f"Unexpected request {request.url}")

    transport = httpx.MockTransport(handler)
    import sentinel.agents.scraper as scraper_module

    previous_now = scraper_module._now_utc
    scraper_module._now_utc = lambda: scraper_module.datetime(2026, 4, 9, 7, 0, 0, tzinfo=scraper_module.UTC)
    async with httpx.AsyncClient(transport=transport) as http_client:
        try:
            agent = ScraperAgent(settings=settings, http_client=http_client)
            records = await agent.run()
        finally:
            scraper_module._now_utc = previous_now

    assert len(records) == 1
    assert records[0].attributes["related_cves"] == ["CVE-2026-12345"]
    assert records[0].reference_url == "https://otx.alienvault.com/pulse/recent"


@pytest.mark.asyncio
async def test_scraper_agent_uses_strict_rolling_24_hour_window(settings: SentinelSettings) -> None:
    settings.sources.max_item_age_hours = 24

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("urlhaus.csv"):
            return httpx.Response(
                200,
                text=(
                    "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
                    "1,2026-04-08 08:30:00,http://recent.test,online,2026-04-08 08:35:00,malware_download,phishing,https://urlhaus.local/1,tester\n"
                    "2,2026-04-08 06:30:00,http://stale.test,online,2026-04-08 06:40:00,malware_download,phishing,https://urlhaus.local/2,tester\n"
                ),
            )
        if request.url.path.endswith("feodo.json"):
            return httpx.Response(200, json=[])
        if request.url.path.endswith("otx"):
            return httpx.Response(200, json={"results": []})
        if request.url.path.endswith("rss.xml"):
            return httpx.Response(200, text="<?xml version='1.0'?><rss version='2.0'><channel></channel></rss>")
        raise AssertionError(f"Unexpected request {request.url}")

    transport = httpx.MockTransport(handler)
    import sentinel.agents.scraper as scraper_module

    async with httpx.AsyncClient(transport=transport) as http_client:
        agent = ScraperAgent(settings=settings, http_client=http_client)
        previous_now = scraper_module._now_utc
        scraper_module._now_utc = lambda: scraper_module.datetime(2026, 4, 9, 7, 0, 0, tzinfo=scraper_module.UTC)
        try:
            records = await agent.run()
        finally:
            scraper_module._now_utc = previous_now

    assert [record.value for record in records] == ["http://recent.test"]


@pytest.mark.asyncio
async def test_scraper_agent_reports_timeout_diagnostic(settings: SentinelSettings) -> None:
    settings.sources.feeds = [
        {"name": "otx", "url": "https://feeds.local/otx", "trust": 0.1},
    ]
    settings.sources.http_timeout_seconds = 0

    class SlowAdapter:
        source_name = "otx"

        async def fetch(self):
            await __import__("asyncio").sleep(0.01)
            return []

    agent = ScraperAgent(settings=settings)
    agent._build_adapters = lambda: [SlowAdapter()]  # type: ignore[method-assign]
    try:
        report = await agent.run_with_diagnostics()
    finally:
        await agent.aclose()

    assert report.items == []
    assert len(report.diagnostics) == 1
    assert report.diagnostics[0].source == "otx"
    assert "TimeoutError" in (report.diagnostics[0].error or "")


@pytest.mark.asyncio
async def test_scraper_agent_uses_skill_trust_scores_and_pushes_queue(settings: SentinelSettings) -> None:
    redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0"><channel><item><title>News</title><link>https://feeds.local/news</link></item></channel></rss>"""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("urlhaus.csv"):
            return httpx.Response(
                200,
                text="id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
                "1,2026-04-08 12:00:00,http://malicious.test,online,2026-04-08 12:05:00,malware_download,phishing,https://urlhaus.local/1,tester\n",
            )
        if request.url.path.endswith("feodo.json"):
            return httpx.Response(
                200,
                json=[{"ip_address": "203.0.113.8", "first_seen": "2026-04-08T12:00:00Z"}],
            )
        if request.url.path.endswith("otx"):
            assert request.headers["X-OTX-API-KEY"] == "test-otx-key"
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "id": "pulse-456",
                            "name": "Pulse",
                            "modified": "2026-04-08T11:00:00Z",
                            "indicators": [
                                {
                                    "id": "indicator-456",
                                    "indicator": "198.51.100.25",
                                    "type": "IPv4",
                                    "created": "2026-04-08T11:00:00Z",
                                }
                            ],
                        }
                    ]
                },
            )
        if request.url.path.endswith("rss.xml"):
            return httpx.Response(200, text=rss_xml)
        raise AssertionError(f"Unexpected request {request.url}")

    transport = httpx.MockTransport(handler)
    import sentinel.agents.scraper as scraper_module

    previous_now = scraper_module._now_utc
    scraper_module._now_utc = lambda: scraper_module.datetime(2026, 4, 9, 7, 0, 0, tzinfo=scraper_module.UTC)
    async with httpx.AsyncClient(transport=transport) as http_client:
        try:
            agent = ScraperAgent(
                settings=settings,
                redis_client=redis_client,
                http_client=http_client,
            )
            records = await agent.run()
        finally:
            scraper_module._now_utc = previous_now

    assert len(records) == 4
    queued = await redis_client.lrange(agent.queue_name, 0, -1)
    assert len(queued) == 4
    payloads = [json.loads(item) for item in queued]
    urlhaus_payload = next(payload for payload in payloads if payload["source"] == "urlhaus")
    assert urlhaus_payload["source_trust"] == 0.91
    rss_payload = next(payload for payload in payloads if payload["source"] == "rss_default")
    assert rss_payload["source_trust"] == 0.6
    await redis_client.aclose()


@pytest.mark.asyncio
async def test_scraper_agent_skips_queue_when_redis_disabled(settings: SentinelSettings) -> None:
    settings.db.redis_url = "disabled"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("urlhaus.csv"):
            return httpx.Response(
                200,
                text="id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
                "1,2026-04-08 12:00:00,http://malicious.test,online,2026-04-08 12:05:00,malware_download,phishing,https://urlhaus.local/1,tester\n",
            )
        if request.url.path.endswith("feodo.json"):
            return httpx.Response(200, json=[{"ip_address": "203.0.113.8", "first_seen": "2026-04-08T12:00:00Z"}])
        if request.url.path.endswith("otx"):
            return httpx.Response(
                200,
                json={"results": [{"id": "pulse-456", "indicators": [{"indicator": "198.51.100.25", "type": "IPv4"}]}]},
            )
        if request.url.path.endswith("rss.xml"):
            return httpx.Response(200, text="<?xml version='1.0'?><rss version='2.0'><channel></channel></rss>")
        raise AssertionError(f"Unexpected request {request.url}")

    transport = httpx.MockTransport(handler)
    import sentinel.agents.scraper as scraper_module

    previous_now = scraper_module._now_utc
    scraper_module._now_utc = lambda: scraper_module.datetime(2026, 4, 9, 7, 0, 0, tzinfo=scraper_module.UTC)
    async with httpx.AsyncClient(transport=transport) as http_client:
        try:
            agent = ScraperAgent(
                settings=settings,
                redis_client=None,
                http_client=http_client,
            )
            records = await agent.run()
        finally:
            scraper_module._now_utc = previous_now

    assert len(records) == 3


@pytest.mark.asyncio
async def test_scraper_agent_reports_diagnostics_for_kept_stale_and_errors(settings: SentinelSettings) -> None:
    import sentinel.agents.scraper as scraper_module
    from sentinel.agents.scraper import RawIOC

    class WorkingAdapter:
        source_name = "working"

        async def fetch(self):
            return [
                RawIOC(
                    value="recent.example",
                    type="domain",
                    source="working",
                    source_trust=0.9,
                    first_seen=scraper_module.datetime(2026, 4, 9, 6, 0, 0, tzinfo=scraper_module.UTC),
                    last_seen=scraper_module.datetime(2026, 4, 9, 6, 0, 0, tzinfo=scraper_module.UTC),
                ),
                RawIOC(
                    value="stale.example",
                    type="domain",
                    source="working",
                    source_trust=0.9,
                    first_seen=scraper_module.datetime(2026, 4, 1, 6, 0, 0, tzinfo=scraper_module.UTC),
                    last_seen=scraper_module.datetime(2026, 4, 1, 6, 0, 0, tzinfo=scraper_module.UTC),
                ),
            ]

    class BrokenAdapter:
        source_name = "broken"

        async def fetch(self):
            raise httpx.ReadTimeout("timed out")

    agent = ScraperAgent(settings=settings)
    previous_now = scraper_module._now_utc
    previous_build = agent._build_adapters
    scraper_module._now_utc = lambda: scraper_module.datetime(2026, 4, 10, 6, 0, 0, tzinfo=scraper_module.UTC)
    agent._build_adapters = lambda: [WorkingAdapter(), BrokenAdapter()]
    try:
        report = await agent.run_with_diagnostics()
    finally:
        scraper_module._now_utc = previous_now
        agent._build_adapters = previous_build
        await agent.aclose()

    assert [item.value for item in report.items] == ["recent.example"]
    assert report.diagnostics == [
        SourceScrapeDiagnostic(source="working", fetched=2, kept=1, stale_dropped=1, error=None),
        SourceScrapeDiagnostic(source="broken", fetched=0, kept=0, stale_dropped=0, error="ReadTimeout: timed out"),
    ]
