from __future__ import annotations

import json

import fakeredis.aioredis
import httpx
import pytest

from sentinel.agents.scraper import (
    FeodoTrackerAdapter,
    MalwareBazaarAdapter,
    OTXPulseAdapter,
    PhishTankAdapter,
    RSSAdapter,
    ScraperAgent,
    SourceScrapeDiagnostic,
    ThreatFoxAdapter,
    URLHausAdapter,
)
from sentinel.config import FeedConfig, SentinelSettings


@pytest.fixture
def settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "sources": {
                "otx_api_key": "test-otx-key",
                "threatfox_api_key": "test-threatfox-key",
                "feeds": [
                    {"name": "threatfox", "url": "https://feeds.local/threatfox", "trust": 0.1},
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
async def test_threatfox_adapter_parses_recent_iocs() -> None:
    seen_headers: dict[str, str] = {}
    seen_json: dict[str, object] = {}

    transport = httpx.MockTransport(
        lambda request: (
            seen_headers.update(dict(request.headers)),
            seen_json.update(json.loads(request.content.decode("utf-8"))),
            httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "data": [
                        {
                            "id": "41",
                            "ioc": "94.103.84.81:443",
                            "ioc_type": "ip:port",
                            "ioc_type_desc": "IP address and port",
                            "threat_type": "botnet_cc",
                            "threat_type_desc": "Command and control",
                            "malware": "win.test",
                            "malware_printable": "Test Malware",
                            "first_seen": "2026-04-10T12:00:00Z",
                            "last_seen": "2026-04-10T13:00:00Z",
                            "confidence_level": 75,
                            "reference": "https://threatfox.abuse.ch/ioc/41/",
                            "tags": ["test"],
                        }
                    ],
                },
            ),
        )[2]
    )
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = ThreatFoxAdapter(
            "https://feeds.local/threatfox",
            trust_score=0.94,
            api_key="threatfox-key",
            lookback_hours=24,
            client=client,
        )
        records = await adapter.fetch()

    assert len(records) == 1
    assert records[0].value == "94.103.84.81"
    assert records[0].type == "ipv4"
    assert records[0].attributes["port"] == 443
    assert records[0].reference_url == "https://threatfox.abuse.ch/ioc/41/"
    assert records[0].attributes["reference_url_original"] == "https://threatfox.abuse.ch/ioc/41/"
    assert seen_headers["auth-key"] == "threatfox-key"
    assert seen_json == {"query": "get_iocs", "days": 1}


@pytest.mark.asyncio
async def test_threatfox_adapter_parses_utc_suffix_timestamps() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "id": "42",
                        "ioc": "203.0.113.20",
                        "ioc_type": "ip",
                        "first_seen": "2026-07-06 18:31:09 UTC",
                        "last_seen": "2026-07-06 18:32:10 UTC",
                    }
                ],
            },
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = ThreatFoxAdapter(
            "https://feeds.local/threatfox",
            trust_score=0.94,
            api_key="threatfox-key",
            client=client,
        )
        records = await adapter.fetch()

    assert len(records) == 1
    assert records[0].first_seen.isoformat() == "2026-07-06T18:31:09+00:00"
    assert records[0].last_seen.isoformat() == "2026-07-06T18:32:10+00:00"


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
async def test_urlhaus_adapter_skips_comment_banner_lines() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            text=(
                "################################################################\n"
                "# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #\n"
                "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
                "\"1\",\"2026-04-08 12:00:00\",\"http://malicious.test\",\"online\","
                "\"2026-04-08 12:05:00\",\"malware_download\",\"phishing\","
                "\"https://urlhaus.local/1\",\"tester\"\n"
            ),
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = URLHausAdapter("https://feeds.local/urlhaus.csv", trust_score=0.91, client=client)
        records = await adapter.fetch()

    assert len(records) == 1
    assert records[0].value == "http://malicious.test"


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
async def test_malwarebazaar_adapter_parses_recent_hash_detections() -> None:
    seen_headers: dict[str, str] = {}
    seen_body = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_body
        seen_headers.update(dict(request.headers))
        seen_body = request.content.decode("utf-8")
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "sha256_hash": "a" * 64,
                        "sha1_hash": "b" * 40,
                        "md5_hash": "c" * 32,
                        "first_seen": "2026-07-06 18:31:09 UTC",
                        "signature": "AgentTesla",
                        "file_name": "invoice.jar",
                        "file_type": "jar",
                        "reporter": "abuse_ch",
                    }
                ],
            },
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        adapter = MalwareBazaarAdapter(
            "https://feeds.local/malwarebazaar",
            trust_score=0.92,
            api_key="mb-key",
            lookback_hours=24,
            client=client,
        )
        records = await adapter.fetch()

    assert {record.type for record in records} == {"md5", "sha1", "sha256"}
    assert all(record.source == "malwarebazaar" for record in records)
    assert all(record.reference_url == f"https://bazaar.abuse.ch/sample/{'a' * 64}/" for record in records)
    assert seen_headers["auth-key"] == "mb-key"
    assert "query=recent_detections" in seen_body


@pytest.mark.asyncio
async def test_phishtank_adapter_parses_verified_urls_and_app_key_path() -> None:
    seen_url = ""
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_url
        seen_url = str(request.url)
        seen_headers.update(dict(request.headers))
        return httpx.Response(
            200,
            json=[
                {
                    "phish_id": "123456",
                    "url": "https://phish.example/login",
                    "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=123456",
                    "submission_time": "2026-07-06T18:15:47+00:00",
                    "verified": "yes",
                    "verification_time": "2026-07-06T18:37:31+00:00",
                    "online": "yes",
                    "target": "Example Bank",
                }
            ],
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = PhishTankAdapter(
            "https://data.phishtank.com/data/online-valid.json",
            trust_score=0.88,
            app_key="pt-key",
            client=client,
        )
        records = await adapter.fetch()

    assert len(records) == 1
    assert records[0].value == "https://phish.example/login"
    assert records[0].type == "url"
    assert records[0].source == "phishtank"
    assert records[0].reference_url == "https://www.phishtank.com/phish_detail.php?phish_id=123456"
    assert "verified_phishing" in records[0].tags
    assert seen_url == "https://data.phishtank.com/data/pt-key/online-valid.json"
    assert seen_headers["user-agent"] == "phishtank/sentinel"


@pytest.mark.asyncio
async def test_rss_adapter_yields_writeups_not_iocs() -> None:
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
        writeups = await adapter.fetch_writeups()

    assert len(writeups) == 1
    assert writeups[0].url == "https://feeds.local/posts/1"
    assert writeups[0].title == "Malware campaign update"
    assert writeups[0].source == "rss_default"
    # Article links are source material, never IOC values.
    assert not hasattr(adapter, "fetch")


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
    assert records[0].reference_url == "https://otx.alienvault.com/pulse/pulse-123"
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
        if request.url.path.endswith("threatfox"):
            return httpx.Response(200, json={"query_status": "ok", "data": []})
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
    assert records[0].reference_url == "https://otx.alienvault.com/pulse/recent-pulse"


@pytest.mark.asyncio
async def test_scraper_agent_uses_strict_rolling_24_hour_window(settings: SentinelSettings) -> None:
    settings.sources.max_item_age_hours = 24

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("threatfox"):
            return httpx.Response(200, json={"query_status": "ok", "data": []})
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
async def test_scraper_agent_uses_separate_writeup_freshness_window(settings: SentinelSettings) -> None:
    settings.sources.max_item_age_hours = 24
    settings.sources.writeup_max_item_age_hours = 72
    settings.db.redis_url = "disabled"
    settings.sources.feeds = [
        FeedConfig(name="talos_blog", url="https://feeds.local/rss.xml", trust=0.68),
    ]
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>SENTINEL Feed</title>
        <item>
          <title>Older but still relevant writeup</title>
          <link>https://articles.local/post-1</link>
          <pubDate>Mon, 07 Apr 2026 12:00:00 GMT</pubDate>
          <description>Campaign infrastructure at hxxp://evil-writeup[.]test/panel.</description>
        </item>
      </channel>
    </rss>"""
    article_html = "<html><body><p>Observed beaconing to 45.155.204.10 and hxxp://evil-writeup[.]test/panel</p></body></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "articles.local":
            return httpx.Response(200, text=article_html)
        if request.url.path.endswith("rss.xml"):
            return httpx.Response(200, text=rss_xml)
        raise AssertionError(f"Unexpected request {request.url}")

    transport = httpx.MockTransport(handler)
    import sentinel.agents.scraper as scraper_module

    previous_now = scraper_module._now_utc
    scraper_module._now_utc = lambda: scraper_module.datetime(2026, 4, 9, 7, 0, 0, tzinfo=scraper_module.UTC)
    async with httpx.AsyncClient(transport=transport) as http_client:
        agent = ScraperAgent(settings=settings, http_client=http_client)
        try:
            report = await agent.run_with_diagnostics()
        finally:
            await agent.aclose()
            scraper_module._now_utc = previous_now

    assert len(report.writeups) == 1
    assert report.writeups[0].source == "talos_blog"
    assert any(record.provenance == "writeup" for record in report.items)
    assert any(diagnostic.source == "talos_blog" and diagnostic.writeups_fetched == 1 for diagnostic in report.diagnostics)


@pytest.mark.asyncio
async def test_scraper_agent_filters_writeups_by_search_terms_and_caps_candidates(settings: SentinelSettings) -> None:
    settings.db.redis_url = "disabled"
    settings.sources.writeup_max_item_age_hours = 72
    settings.sources.writeup_search.terms = ["phishing", "stealer"]
    settings.sources.writeup_search.max_candidates_per_source = 1
    settings.sources.feeds = [
        FeedConfig(name="gbhackers_blog", url="https://feeds.local/rss.xml", trust=0.64),
    ]
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>Phishing campaign delivers stealer</title>
          <link>https://articles.local/post-1</link>
          <pubDate>Wed, 08 Apr 2026 12:00:00 GMT</pubDate>
          <description>hxxps[:]//evil-one[.]test/dropper</description>
        </item>
        <item>
          <title>Quarterly product roundup</title>
          <link>https://articles.local/post-2</link>
          <pubDate>Wed, 08 Apr 2026 11:00:00 GMT</pubDate>
          <description>No threat content here.</description>
        </item>
        <item>
          <title>Another phishing lure</title>
          <link>https://articles.local/post-3</link>
          <pubDate>Wed, 08 Apr 2026 10:00:00 GMT</pubDate>
          <description>hxxps[:]//evil-two[.]test/payload</description>
        </item>
      </channel>
    </rss>"""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "articles.local":
            return httpx.Response(200, text="<html><body>Payload at hxxps[:]//evil-one[.]test/dropper</body></html>")
        if request.url.path.endswith("rss.xml"):
            return httpx.Response(200, text=rss_xml)
        raise AssertionError(f"Unexpected request {request.url}")

    transport = httpx.MockTransport(handler)
    import sentinel.agents.scraper as scraper_module

    previous_now = scraper_module._now_utc
    scraper_module._now_utc = lambda: scraper_module.datetime(2026, 4, 9, 7, 0, 0, tzinfo=scraper_module.UTC)
    async with httpx.AsyncClient(transport=transport) as http_client:
        agent = ScraperAgent(settings=settings, http_client=http_client)
        try:
            report = await agent.run_with_diagnostics()
        finally:
            await agent.aclose()
            scraper_module._now_utc = previous_now

    assert len(report.writeups) == 1
    assert report.writeups[0].url == "https://articles.local/post-1"
    assert any(record.value == "https://evil-one.test/dropper" for record in report.items)
    assert all("post-3" not in (record.reference_url or "") for record in report.items)


@pytest.mark.asyncio
async def test_scraper_agent_uses_browser_headers_for_article_fetches(settings: SentinelSettings) -> None:
    settings.db.redis_url = "disabled"
    settings.sources.feeds = [
        FeedConfig(name="gbhackers_blog", url="https://feeds.local/rss.xml", trust=0.64),
    ]
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>Phishing campaign delivers stealer</title>
          <link>https://articles.local/post-1</link>
          <pubDate>Wed, 08 Apr 2026 12:00:00 GMT</pubDate>
          <description>hxxps[:]//evil-one[.]test/dropper</description>
        </item>
      </channel>
    </rss>"""
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "articles.local":
            seen_headers.update(dict(request.headers))
            return httpx.Response(200, text="<html><body>Payload at hxxps[:]//evil-one[.]test/dropper</body></html>")
        if request.url.path.endswith("rss.xml"):
            return httpx.Response(200, text=rss_xml)
        raise AssertionError(f"Unexpected request {request.url}")

    transport = httpx.MockTransport(handler)
    import sentinel.agents.scraper as scraper_module

    previous_now = scraper_module._now_utc
    scraper_module._now_utc = lambda: scraper_module.datetime(2026, 4, 9, 7, 0, 0, tzinfo=scraper_module.UTC)
    async with httpx.AsyncClient(transport=transport) as http_client:
        agent = ScraperAgent(settings=settings, http_client=http_client)
        try:
            report = await agent.run_with_diagnostics()
        finally:
            await agent.aclose()
            scraper_module._now_utc = previous_now

    assert report.writeups
    assert seen_headers["user-agent"].startswith("Mozilla/5.0")
    assert seen_headers["accept-language"] == "en-US,en;q=0.9"
    assert seen_headers["referer"] == "https://articles.local/post-1"


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
    agent._build_adapters = lambda: ([SlowAdapter()], [])  # type: ignore[method-assign]
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
    # Title must hit a writeup_search term or the keyword filter drops the item
    # before the body is ever fetched.
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0"><channel><item><title>Malware campaign news</title><link>https://articles.local/news</link></item></channel></rss>"""
    article_html = (
        "<html><body><p>Campaign C2 at 45.155.204.10 delivering payloads from "
        "hxxp://evil-payload[.]top/gate.php targeting exposed servers.</p></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "articles.local" and request.url.path.endswith("news"):
            return httpx.Response(200, text=article_html)
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
        if request.url.path.endswith("threatfox"):
            return httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "data": [
                        {
                            "id": "41",
                            "ioc": "94.103.84.81",
                            "ioc_type": "ip",
                            "first_seen": "2026-04-08T12:00:00Z",
                            "last_seen": "2026-04-08T13:00:00Z",
                            "reference": "https://threatfox.abuse.ch/ioc/41/",
                        }
                    ],
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
            report = await agent.run_with_diagnostics()
            records = report.items
        finally:
            scraper_module._now_utc = previous_now

    # 4 direct feed IOCs + 2 extracted from the article body (refanged URL and
    # C2 IP). The bare domain inside that defanged URL is intentionally not
    # emitted as a duplicate standalone IOC.
    assert len(records) == 6
    assert len(report.writeups) == 1
    assert report.writeups[0].url == "https://articles.local/news"
    extracted = [record for record in records if record.provenance == "writeup"]
    assert {record.value for record in extracted} == {
        "http://evil-payload.top/gate.php",
        "45.155.204.10",
    }
    assert all(record.reference_url == "https://articles.local/news" for record in extracted)
    queued = await redis_client.lrange(agent.queue_name, 0, -1)
    assert len(queued) == 6
    payloads = [json.loads(item) for item in queued]
    urlhaus_payload = next(payload for payload in payloads if payload["source"] == "urlhaus")
    assert urlhaus_payload["source_trust"] == 0.91
    # rss_default is not listed in the skill file's Trust Scores, so it keeps
    # the config fixture trust — proving the fallback path (urlhaus above
    # proves the skill-override path).
    rss_payload = next(payload for payload in payloads if payload["source"] == "rss_default")
    assert rss_payload["source_trust"] == 0.1
    assert rss_payload["provenance"] == "writeup"
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
    agent._build_adapters = lambda: ([WorkingAdapter(), BrokenAdapter()], [])
    try:
        report = await agent.run_with_diagnostics()
    finally:
        scraper_module._now_utc = previous_now
        agent._build_adapters = previous_build
        await agent.aclose()

    assert [item.value for item in report.items] == ["recent.example"]
    assert report.diagnostics == [
        SourceScrapeDiagnostic(source="working", fetched=2, pre_balance_kept=1, kept=1, stale_dropped=1, error=None),
        SourceScrapeDiagnostic(source="broken", fetched=0, kept=0, stale_dropped=0, error="ReadTimeout: timed out"),
    ]


@pytest.mark.asyncio
async def test_scraper_agent_caps_dominant_sources_and_records_balance_drop(settings: SentinelSettings) -> None:
    import sentinel.agents.scraper as scraper_module
    from sentinel.agents.scraper import RawIOC

    settings.sources.mix.enabled = True
    settings.sources.mix.max_items_per_source = 2
    previous_now = scraper_module._now_utc
    scraper_module._now_utc = lambda: scraper_module.datetime(2026, 4, 10, 11, 0, 0, tzinfo=scraper_module.UTC)

    def make_item(value: str, source: str, hour: int) -> RawIOC:
        seen = scraper_module.datetime(2026, 4, 10, hour, 0, 0, tzinfo=scraper_module.UTC)
        return RawIOC(
            value=value,
            type="domain",
            source=source,
            source_trust=0.9,
            first_seen=seen,
            last_seen=seen,
        )

    class URLHausAdapterStub:
        source_name = "urlhaus"

        async def fetch(self):
            return [
                make_item("urlhaus-1.example", "urlhaus", 10),
                make_item("urlhaus-2.example", "urlhaus", 9),
                make_item("urlhaus-3.example", "urlhaus", 8),
            ]

    class ThreatFoxAdapterStub:
        source_name = "threatfox"

        async def fetch(self):
            return [
                make_item("threatfox-1.example", "threatfox", 10),
                make_item("threatfox-2.example", "threatfox", 9),
                make_item("threatfox-3.example", "threatfox", 8),
            ]

    class OTXAdapterStub:
        source_name = "otx"

        async def fetch(self):
            return [make_item("otx-1.example", "otx", 7)]

    agent = ScraperAgent(settings=settings)
    previous_build = agent._build_adapters
    agent._build_adapters = lambda: ([URLHausAdapterStub(), ThreatFoxAdapterStub(), OTXAdapterStub()], [])
    try:
        report = await agent.run_with_diagnostics()
    finally:
        scraper_module._now_utc = previous_now
        agent._build_adapters = previous_build
        await agent.aclose()

    assert [item.source for item in report.items] == ["urlhaus", "threatfox", "otx", "urlhaus", "threatfox"]
    by_source = {diagnostic.source: diagnostic for diagnostic in report.diagnostics}
    assert by_source["urlhaus"].pre_balance_kept == 3
    assert by_source["urlhaus"].kept == 2
    assert by_source["urlhaus"].balance_dropped == 1
    assert by_source["threatfox"].pre_balance_kept == 3
    assert by_source["threatfox"].kept == 2
    assert by_source["threatfox"].balance_dropped == 1
    assert by_source["otx"].pre_balance_kept == 1
    assert by_source["otx"].kept == 1
    assert by_source["otx"].balance_dropped == 0


@pytest.mark.asyncio
async def test_writeup_extraction_marks_ioc_section_for_curation_credit(settings: SentinelSettings) -> None:
    """A writeup whose body has an explicit IOC section is tagged
    extraction_mode=ioc_section so its indicators earn full scoring context;
    a writeup without one falls back."""
    from sentinel.agents.scraper import RawWriteup

    agent = ScraperAgent(settings=settings)
    try:
        curated = RawWriteup(
            source="securelist_blog",
            source_trust=0.67,
            url="https://securelist.com/campaign",
            title="Stealer campaign",
            published_at=__import__("sentinel.agents.scraper", fromlist=["_now_utc"])._now_utc(),
            content_text=(
                "Our team analysed a stealer campaign.\n"
                "Indicators of Compromise\n"
                "malicious-c2.badcorp.top\n"
                "45.155.204.99\n"
                "d41d8cd98f00b204e9800998ecf8427e\n"
                "Conclusion\n"
                "Block the above."
            ),
        )
        prose_only = RawWriteup(
            source="securelist_blog",
            source_trust=0.67,
            url="https://securelist.com/thoughts",
            title="Threat landscape musings",
            published_at=__import__("sentinel.agents.scraper", fromlist=["_now_utc"])._now_utc(),
            content_text="A long reflection on the evolving threat landscape with no indicators.",
        )

        curated_items = agent._extract_iocs_from_writeup(curated)
        prose_items = agent._extract_iocs_from_writeup(prose_only)
    finally:
        await agent.aclose()

    assert curated_items
    assert all(item.attributes["extraction_mode"] == "ioc_section" for item in curated_items)
    assert all(item.provenance == "writeup" for item in curated_items)
    assert {"malicious-c2.badcorp.top", "45.155.204.99"} <= {item.value for item in curated_items}
    # No section -> fallback labeling (may still find defanged/urls, but not curated).
    assert all(item.attributes["extraction_mode"] == "fallback" for item in prose_items)


def test_writeup_extraction_caps_ioc_section_article_yield(settings: SentinelSettings) -> None:
    from sentinel.agents.scraper import RawWriteup

    settings.sources.writeup_search.max_iocs_per_article_ioc_section = 3
    agent = ScraperAgent(settings=settings)
    writeup = RawWriteup(
        source="rapid7_blog",
        source_trust=0.8,
        url="https://www.rapid7.com/blog/post/example/",
        title="Rapid7 large IOC appendix",
        published_at=__import__("sentinel.agents.scraper", fromlist=["_now_utc"])._now_utc(),
        content_text=(
            "Indicators of Compromise\n"
            "alpha.bad.example\n"
            "beta.bad.example\n"
            "gamma.bad.example\n"
            "delta.bad.example\n"
            "epsilon.bad.example\n"
        ),
    )

    items = agent._extract_iocs_from_writeup(writeup)

    assert len(items) == 3
    assert all(item.attributes["extraction_mode"] == "ioc_section" for item in items)
