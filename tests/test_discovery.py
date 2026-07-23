from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from sentinel.agents.discovery import (
    Candidate,
    DiscoveryAgent,
    DiscoveryMemoryStore,
    format_discovery_report,
)
from sentinel.agents.ioc_extract import html_to_text
from sentinel.agents.scraper import RawWriteup
from sentinel.config import SentinelSettings
from sentinel.db.models import DiscoveryMemory, FeedbackRecord, IOC, IOCSighting


NOW = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)


def rss_feed(items: list[dict[str, str]]) -> str:
    entries = "".join(
        f"<item><title>{item['title']}</title><link>{item['link']}</link>"
        f"<pubDate>{item.get('published', 'Fri, 03 Jul 2026 09:00:00 GMT')}</pubDate>"
        f"<description>{item.get('summary', '')}</description></item>"
        for item in items
    )
    return f'<?xml version="1.0"?><rss version="2.0"><channel>{entries}</channel></rss>'


def gdelt_payload(articles: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    return {"articles": articles}


ARTICLE_WITH_SECTION = """
<html><body>
<h1>New stealer campaign targets credentials</h1>
<p>We observed a new campaign delivering a credential stealer via phishing.</p>
<h2>Indicators of Compromise</h2>
<ul>
<li>malicious-c2.badcorp.io</li>
<li>45.155.204.99</li>
<li>d41d8cd98f00b204e9800998ecf8427e</li>
</ul>
<h2>Conclusion</h2>
<p>Stay safe out there.</p>
</body></html>
"""

ARTICLE_WITH_PUBLISHER_DOMAIN_AND_CVES = """
<html><body>
<h1>wp2shell hits WordPress</h1>
<p>Elastic published this research from elastic[.]co.</p>
<h2>Indicators of Compromise</h2>
<ul>
<li>elastic.co</li>
<li>CVE-2026-63030</li>
<li>CVE-2026-60137</li>
</ul>
</body></html>
"""

ARTICLE_WITHOUT_SECTION = """
<html><body>
<h1>Thought leadership on the threat landscape</h1>
<p>Attackers continue to attack and defenders continue to defend across every
industry vertical we monitor. Our researchers spent the last quarter reviewing
incident response engagements, tabletop exercises, and purple team outcomes to
understand where security programs are maturing and where they still struggle.
The conclusions are unsurprising but worth repeating: patch discipline,
credential hygiene, and rehearsed response playbooks remain the difference
between a contained incident and a headline. Read our whitepaper for the full
narrative treatment of these findings and our guidance for the year ahead.</p>
</body></html>
"""

SUMMARY_WITH_SECTION = """
<h2>Indicators of Compromise</h2>
<ul>
<li>hxxps[:]//inventory-card-thumbzilla-ip[.]trycloudflare[.]com/De/</li>
<li>62.60.190.141</li>
<li>55724b766dd1fe8bf9dd4cb7094b83b88d57d945</li>
</ul>
"""


def build_settings(profile_overrides: dict | None = None) -> SentinelSettings:
    profile = {
        "name": "test-profile",
        "enabled": True,
        "keywords": ["stealer", "phishing", "ioc", "c2"],
        "feeds": ["https://feeds.local/blog.xml"],
        "freshness_hours": 96,
        "max_candidates_per_source": 10,
        "max_pages_per_run": 4,
        "time_budget_seconds": 30,
        "per_page_timeout_seconds": 5,
        "require_ioc_section": True,
        "source_trust": 0.6,
        **(profile_overrides or {}),
    }
    return SentinelSettings.model_validate(
        {
            "discovery": {"enabled": True, "profiles": [profile]},
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "disabled"},
        }
    )


def build_agent(
    settings: SentinelSettings,
    transport: httpx.MockTransport,
    session_factory,
    *,
    skill_path: str = "skills/discovery/SKILL.md",
) -> DiscoveryAgent:
    return DiscoveryAgent(
        skill_path=skill_path,
        settings=settings,
        http_client=httpx.AsyncClient(transport=transport),
        session_factory=session_factory,
        now_fn=lambda: NOW,
    )


def routes(feed_items: list[dict[str, str]], pages: dict[str, str]):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("blog.xml"):
            return httpx.Response(200, text=rss_feed(feed_items))
        for path, html in pages.items():
            if request.url.path == path:
                return httpx.Response(200, text=html)
        return httpx.Response(404, text="not found")

    return handler


@pytest.mark.asyncio
async def test_discovery_extracts_from_ioc_section_with_attribution(db_session_factory) -> None:
    feed = [
        {"title": "New stealer campaign with IOCs", "link": "https://blog.vendor.test/stealer-campaign"},
    ]
    transport = httpx.MockTransport(routes(feed, {"/stealer-campaign": ARTICLE_WITH_SECTION}))
    agent = build_agent(
        build_settings({"time_budget_seconds": 3, "per_page_timeout_seconds": 1}),
        transport,
        db_session_factory,
    )
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    assert len(report.writeups) == 1
    values = {(item.type, item.value) for item in report.items}
    assert ("domain", "malicious-c2.badcorp.io") in values
    assert ("ipv4", "45.155.204.99") in values
    assert ("md5", "d41d8cd98f00b204e9800998ecf8427e") in values
    item = report.items[0]
    assert item.provenance == "discovery"
    assert item.attributes["search_profile"] == "test-profile"
    assert item.attributes["extraction_mode"] == "ioc_section"
    assert "stealer" in item.attributes["matched_keywords"]
    assert item.reference_url == "https://blog.vendor.test/stealer-campaign"
    diagnostic = report.diagnostics[0]
    assert diagnostic.pages_fetched == 1
    assert diagnostic.iocs_extracted == 3


@pytest.mark.asyncio
async def test_discovery_excludes_publisher_domain_from_article_iocs() -> None:
    settings = build_settings()
    agent = DiscoveryAgent(
        settings=settings,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(404))),
        now_fn=lambda: NOW,
    )
    writeup = RawWriteup(
        source="discovery:www.elastic.co",
        source_trust=0.6,
        url="https://www.elastic.co/security-labs/wp2shell-wordpress-rce-detection-elastic-defend",
        title="wp2shell IOC CVE research",
        published_at=NOW,
    )
    try:
        items, section_signal, failure_reason = agent._extract_candidate_items(
            settings.discovery.profiles[0],
            Candidate(writeup=writeup, score=1.0, matched_keywords=["ioc", "cve"]),
            html_to_text(ARTICLE_WITH_PUBLISHER_DOMAIN_AND_CVES),
            origin="page",
        )
    finally:
        await agent.http_client.aclose()

    values = {(item.type, item.value) for item in items}
    assert values == {
        ("cve", "CVE-2026-63030"),
        ("cve", "CVE-2026-60137"),
    }
    assert section_signal == "heading"
    assert failure_reason is None


@pytest.mark.asyncio
async def test_strict_profile_skips_pages_without_ioc_section(db_session_factory) -> None:
    feed = [
        {"title": "Thought leadership on phishing threats", "link": "https://blog.vendor.test/fluff"},
    ]
    transport = httpx.MockTransport(routes(feed, {"/fluff": ARTICLE_WITHOUT_SECTION}))
    agent = build_agent(build_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    assert report.items == []
    assert report.diagnostics[0].skipped_no_section == 1


@pytest.mark.asyncio
async def test_triage_skips_keyword_poor_candidates_before_fetching(db_session_factory) -> None:
    feed = [
        {"title": "Our quarterly business update", "link": "https://blog.vendor.test/business", "summary": "Revenue grew."},
        {"title": "Stealer campaign IOC breakdown", "link": "https://blog.vendor.test/stealer-campaign", "summary": "phishing c2"},
    ]
    transport = httpx.MockTransport(routes(feed, {"/stealer-campaign": ARTICLE_WITH_SECTION}))
    agent = build_agent(build_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    # The business post never passes triage, so its page is never requested.
    assert diagnostic.skipped_low_score == 1
    assert diagnostic.pages_fetched == 1
    assert len(report.items) == 3


@pytest.mark.asyncio
async def test_deny_hosts_and_max_pages_bound_the_run(db_session_factory) -> None:
    feed = [
        {"title": "Stealer IOC report A", "link": "https://blog.vendor.test/a"},
        {"title": "Stealer IOC report B", "link": "https://denied.test/b"},
        {"title": "Stealer IOC report C", "link": "https://blog.vendor.test/c"},
    ]
    transport = httpx.MockTransport(
        routes(feed, {"/a": ARTICLE_WITH_SECTION, "/c": ARTICLE_WITH_SECTION})
    )
    settings = build_settings({"deny_hosts": ["denied.test"], "max_pages_per_run": 1})
    agent = build_agent(settings, transport, db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    assert diagnostic.skipped_denied_host == 1
    assert diagnostic.pages_fetched == 1  # max_pages_per_run caps spend


@pytest.mark.asyncio
async def test_time_budget_stops_fetching_remaining_pages(db_session_factory) -> None:
    feed = [
        {"title": "Stealer IOC report A", "link": "https://blog.vendor.test/a"},
        {"title": "Stealer IOC report B", "link": "https://blog.vendor.test/b"},
        {"title": "Stealer IOC report C", "link": "https://blog.vendor.test/c"},
    ]

    async def slow_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("blog.xml"):
            return httpx.Response(200, text=rss_feed(feed))
        # Each page takes longer than the whole 1s budget (the config minimum),
        # so page A times out against the budget and B/C never start.
        await asyncio.sleep(1.5)
        return httpx.Response(200, text=ARTICLE_WITH_SECTION)

    transport = httpx.MockTransport(slow_handler)
    settings = build_settings({"time_budget_seconds": 1, "per_page_timeout_seconds": 30})
    agent = build_agent(settings, transport, db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    assert diagnostic.pages_fetched == 0
    assert diagnostic.fetch_errors == 1
    assert diagnostic.skipped_budget == 2
    assert report.items == []


@pytest.mark.asyncio
async def test_discovery_search_provider_fetches_open_web_candidates(db_session_factory) -> None:
    settings = build_settings(
        {
            "feeds": [],
            "search_providers": [
                {
                    "name": "open-web",
                    "provider": "gdelt_doc",
                    "query_terms": ["phishing", "stealer"],
                    "max_queries": 2,
                    "max_records": 5,
                }
            ],
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.gdeltproject.org":
            return httpx.Response(
                200,
                json=gdelt_payload(
                    [
                        {
                            "url": "https://news.vendor.test/phish-report",
                            "title": "Phishing report with IOCs",
                            "domain": "news.vendor.test",
                            "seendate": "20260703103000",
                        }
                    ]
                ),
            )
        return httpx.Response(200, text=ARTICLE_WITH_SECTION)

    agent = build_agent(settings, httpx.MockTransport(handler), db_session_factory)
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    assert len(report.items) == 3
    assert all(item.source == "discovery:news.vendor.test" for item in report.items)


@pytest.mark.asyncio
async def test_discovery_search_provider_uses_query_terms_and_time_window(db_session_factory) -> None:
    settings = build_settings(
        {
            "feeds": [],
            "freshness_hours": 48,
            "search_providers": [
                {
                    "name": "open-web",
                    "provider": "gdelt_doc",
                    "query_terms": ["indicators of compromise", "phishing"],
                    "max_queries": 1,
                    "max_records": 5,
                }
            ],
        }
    )
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.gdeltproject.org":
            seen["query"] = request.url.params.get("query", "")
            seen["startdatetime"] = request.url.params.get("startdatetime", "")
            seen["enddatetime"] = request.url.params.get("enddatetime", "")
            return httpx.Response(200, json=gdelt_payload([]))
        return httpx.Response(404, text="not found")

    agent = build_agent(settings, httpx.MockTransport(handler), db_session_factory)
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    assert report.items == []
    assert seen["query"] == '"indicators of compromise"'
    assert seen["startdatetime"] == "20260701120000"
    assert seen["enddatetime"] == "20260703120000"


@pytest.mark.asyncio
async def test_discovery_search_provider_keeps_earlier_results_after_rate_limit(db_session_factory) -> None:
    settings = build_settings(
        {
            "feeds": [],
            "search_providers": [
                {
                    "name": "open-web",
                    "provider": "gdelt_doc",
                    "query_terms": ["phishing", "stealer", "malware"],
                    "max_queries": 3,
                    "max_records": 5,
                }
            ],
        }
    )
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.gdeltproject.org":
            query = request.url.params.get("query", "")
            calls.append(query)
            if query == "malware":
                return httpx.Response(429, json={"articles": []})
            return httpx.Response(
                200,
                json=gdelt_payload(
                    [
                        {
                            "url": f"https://news.vendor.test/{query}",
                            "title": f"{query.title()} report with IOCs",
                            "domain": "news.vendor.test",
                            "seendate": "20260703103000",
                        }
                    ]
                ),
            )
        return httpx.Response(200, text=ARTICLE_WITH_SECTION)

    agent = build_agent(settings, httpx.MockTransport(handler), db_session_factory)
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    assert calls == ["phishing", "stealer", "malware"]
    assert len(report.items) == 6
    assert all(item.source == "discovery:news.vendor.test" for item in report.items)


@pytest.mark.asyncio
async def test_discovery_search_provider_skips_malformed_json_and_continues(db_session_factory) -> None:
    settings = build_settings(
        {
            "feeds": [],
            "search_providers": [
                {
                    "name": "open-web",
                    "provider": "gdelt_doc",
                    "query_terms": ["phishing", "stealer"],
                    "max_queries": 2,
                    "max_records": 5,
                }
            ],
        }
    )
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.gdeltproject.org":
            query = request.url.params.get("query", "")
            calls.append(query)
            if query == "phishing":
                return httpx.Response(200, text="not-json-but-still-200")
            return httpx.Response(
                200,
                json=gdelt_payload(
                    [
                        {
                            "url": "https://news.vendor.test/stealer",
                            "title": "Stealer report with IOCs",
                            "domain": "news.vendor.test",
                            "seendate": "20260703103000",
                        }
                    ]
                ),
            )
        return httpx.Response(200, text=ARTICLE_WITH_SECTION)

    agent = build_agent(settings, httpx.MockTransport(handler), db_session_factory)
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    assert calls == ["phishing", "stealer"]
    assert len(report.items) == 3
    assert all(item.source == "discovery:news.vendor.test" for item in report.items)


@pytest.mark.asyncio
async def test_discovery_google_news_provider_builds_recent_query_and_extracts(db_session_factory) -> None:
    settings = build_settings(
        {
            "feeds": [],
            "freshness_hours": 48,
            "search_providers": [
                {
                    "name": "google-news",
                    "provider": "google_news_rss",
                    "base_url": "https://news.google.com/rss/search",
                    "query_terms": ["phishing"],
                    "max_queries": 1,
                    "max_records": 5,
                }
            ],
        }
    )
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "news.google.com":
            seen["q"] = request.url.params.get("q", "")
            return httpx.Response(
                200,
                text=rss_feed(
                    [
                        {
                            "title": "Phishing report with IOCs",
                            "link": "https://news.vendor.test/phish-report",
                            "summary": "IOC-heavy writeup",
                            "published": "Fri, 03 Jul 2026 09:00:00 GMT",
                        }
                    ]
                ),
            )
        return httpx.Response(200, text=ARTICLE_WITH_SECTION)

    agent = build_agent(settings, httpx.MockTransport(handler), db_session_factory)
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    assert seen["q"] == "phishing when:2d"
    assert len(report.items) == 3
    assert all(item.source == "discovery:news.vendor.test" for item in report.items)


@pytest.mark.asyncio
async def test_discovery_resolves_google_news_wrapper_to_publisher_article(db_session_factory) -> None:
    settings = build_settings(
        {
            "feeds": [],
            "search_providers": [
                {
                    "name": "google-news",
                    "provider": "google_news_rss",
                    "base_url": "https://news.google.com/rss/search",
                    "query_terms": ["phishing"],
                    "max_queries": 1,
                    "max_records": 5,
                }
            ],
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "news.google.com" and request.url.path == "/rss/search":
            return httpx.Response(
                200,
                text=rss_feed(
                    [
                        {
                            "title": "Phishing report with IOCs",
                            "link": "https://news.google.com/rss/articles/CBMi-test",
                            "summary": "IOC-heavy writeup",
                            "published": "Fri, 03 Jul 2026 09:00:00 GMT",
                        }
                    ]
                ),
            )
        if request.url.host == "news.google.com":
            return httpx.Response(
                200,
                text=(
                    '<html><head><link rel="canonical" '
                    'href="https://publisher.example/phish-report"></head><body></body></html>'
                ),
            )
        if request.url.host == "publisher.example":
            return httpx.Response(200, text=ARTICLE_WITH_SECTION)
        return httpx.Response(404, text="not found")

    agent = build_agent(settings, httpx.MockTransport(handler), db_session_factory)
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    assert len(report.items) == 3
    assert all(item.reference_url == "https://publisher.example/phish-report" for item in report.items)


def test_extract_canonical_article_url_ignores_google_image_urls() -> None:
    html = """
    <html><head>
    <meta property="og:url" content="https://lh3.googleusercontent.com/example=w16">
    <link rel="canonical" href="https://publisher.example/phish-report">
    </head></html>
    """
    resolved = DiscoveryAgent._extract_canonical_article_url(
        html,
        base_url="https://news.google.com/rss/articles/CBMi-test",
    )
    assert resolved == "https://publisher.example/phish-report"


def test_extract_canonical_article_url_skips_single_slug_utility_page_for_publisher_url() -> None:
    html = """
    <html><head>
    <link rel="canonical" href="https://angular.dev/license">
    </head><body>
    <c-wiz data-n-au="https://securelist.com/armored-likho-apt-with-busysnake-stealer/"></c-wiz>
    </body></html>
    """
    resolved = DiscoveryAgent._extract_canonical_article_url(
        html,
        base_url="https://news.google.com/rss/articles/CBMi-test",
    )
    assert resolved == "https://securelist.com/armored-likho-apt-with-busysnake-stealer/"


@pytest.mark.asyncio
async def test_lenient_profile_falls_back_to_body_extraction(db_session_factory) -> None:
    body = """
    <html><body>
    <h1>Phishing wave analysis</h1>
    <p>The campaign used hxxps://phish-kit[.]bad/login and hxxp://drop[.]bad/x plus
    C2 at 45.155.204.7 and more C2 at 45.155.204.8.</p>
    </body></html>
    """
    feed = [{"title": "Phishing IOC wave", "link": "https://blog.vendor.test/wave"}]
    transport = httpx.MockTransport(routes(feed, {"/wave": body}))
    settings = build_settings({"require_ioc_section": False})
    agent = build_agent(settings, transport, db_session_factory)

    report = await agent.run_with_report()

    assert len(report.items) >= 3
    assert all(item.attributes["extraction_mode"] == "fallback" for item in report.items)


@pytest.mark.asyncio
async def test_discovery_uses_browser_headers_for_article_fetch(db_session_factory) -> None:
    seen_headers: dict[str, str] = {}
    feed = [{"title": "Stealer campaign with IOCs", "link": "https://blog.vendor.test/stealer-campaign"}]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("blog.xml"):
            return httpx.Response(200, text=rss_feed(feed))
        seen_headers["user-agent"] = request.headers.get("user-agent", "")
        seen_headers["accept-language"] = request.headers.get("accept-language", "")
        seen_headers["referer"] = request.headers.get("referer", "")
        return httpx.Response(200, text=ARTICLE_WITH_SECTION)

    agent = build_agent(build_settings(), httpx.MockTransport(handler), db_session_factory)
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    assert len(report.items) == 3
    assert "mozilla" in seen_headers["user-agent"].lower()
    assert seen_headers["accept-language"].startswith("en-US")
    assert seen_headers["referer"] == "https://blog.vendor.test/"


@pytest.mark.asyncio
async def test_discovery_extracts_from_feed_summary_when_article_fetch_is_blocked(db_session_factory) -> None:
    feed = [
        {
            "title": "Fake invoice phishing campaign with IOCs",
            "link": "https://gbhackers.com/fake-invoice-pdf/",
            "summary": SUMMARY_WITH_SECTION,
        }
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("blog.xml"):
            return httpx.Response(200, text=rss_feed(feed))
        return httpx.Response(403, text="forbidden")

    agent = build_agent(build_settings(), httpx.MockTransport(handler), db_session_factory)
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    values = {(item.type, item.value) for item in report.items}
    assert ("url", "https://inventory-card-thumbzilla-ip.trycloudflare.com/De/") in values
    assert ("ipv4", "62.60.190.141") in values
    assert ("sha1", "55724b766dd1fe8bf9dd4cb7094b83b88d57d945") in values
    assert report.diagnostics[0].fetch_errors == 1
    assert report.diagnostics[0].pages_fetched == 0
    assert report.diagnostics[0].iocs_extracted == 3
    assert all(item.attributes["extraction_mode"] == "feed_summary" for item in report.items)


GOOGLE_WRAPPER_ONLY_ASSETS = """
<html><head>
<link href="https://fonts.googleapis.com/css2?family=Google+Sans+Text:wght@400" rel="stylesheet">
<script src="https://www.gstatic.com/_/mss/boq-news/_/js/k=boq-news.js"></script>
</head><body>
<img src="https://lh3.googleusercontent.com/example=w200">
<c-wiz>Opening the article…</c-wiz>
</body></html>
"""

GOOGLE_WRAPPER_MIXED = """
<html><head>
<link href="https://fonts.googleapis.com/css2?family=Google+Sans+Text:wght@400" rel="stylesheet">
<script src="https://www.gstatic.com/_/mss/boq-news/_/js/k=boq-news.js"></script>
</head><body>
<img src="https://lh3.googleusercontent.com/example=w200">
<a href="https://publisher.test/threat-report" rel="nofollow">Read the story</a>
</body></html>
"""


def google_news_routes(pages: dict[str, str], *, wrapper_html: str, seen: list[str]):
    """Feed -> wrapper -> optional publisher pages, recording every request."""

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "news.google.com" and request.url.path == "/rss/search":
            return httpx.Response(
                200,
                text=rss_feed(
                    [
                        {
                            "title": "Stealer campaign IOC report",
                            "link": "https://news.google.com/rss/articles/CBMi-wrapped",
                        }
                    ]
                ),
            )
        if request.url.host == "news.google.com":
            return httpx.Response(200, text=wrapper_html)
        for path, html in pages.items():
            if request.url.path == path:
                return httpx.Response(200, text=html)
        return httpx.Response(404, text="not found")

    return handler


def google_news_settings() -> SentinelSettings:
    return build_settings(
        {
            "feeds": [],
            "search_providers": [
                {
                    "name": "google-news",
                    "provider": "google_news_rss",
                    "base_url": "https://news.google.com/rss/search",
                    "query_terms": ["stealer ioc"],
                }
            ],
        }
    )


@pytest.mark.asyncio
async def test_wrapper_with_only_asset_urls_is_discarded_cleanly(db_session_factory) -> None:
    seen: list[str] = []
    transport = httpx.MockTransport(
        google_news_routes({}, wrapper_html=GOOGLE_WRAPPER_ONLY_ASSETS, seen=seen)
    )
    agent = build_agent(google_news_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    assert report.items == []
    assert diagnostic.skipped_non_article == 1
    assert diagnostic.pages_fetched == 0
    assert diagnostic.skipped_no_section == 0  # not misclassified as a section miss
    # The fonts/gstatic URLs were never treated as the article and never fetched.
    assert not any("fonts.googleapis.com" in url for url in seen)
    assert not any("gstatic.com" in url for url in seen)


@pytest.mark.asyncio
async def test_wrapper_with_mixed_asset_and_publisher_urls_resolves_publisher(db_session_factory) -> None:
    seen: list[str] = []
    transport = httpx.MockTransport(
        google_news_routes(
            {"/threat-report": ARTICLE_WITH_SECTION},
            wrapper_html=GOOGLE_WRAPPER_MIXED,
            seen=seen,
        )
    )
    agent = build_agent(google_news_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    assert diagnostic.wrapper_resolved == 1
    assert diagnostic.pages_fetched == 1
    assert len(report.items) == 3
    # Every extracted item carries the publisher article URL, not the wrapper.
    assert all(item.reference_url == "https://publisher.test/threat-report" for item in report.items)
    assert all(item.attributes["article_url"] == "https://publisher.test/threat-report" for item in report.items)
    # Source attribution moves to the publisher for memory learning.
    assert all(item.source == "discovery:publisher.test" for item in report.items)
    assert not any("fonts.googleapis.com" in url for url in seen)


@pytest.mark.asyncio
async def test_wrapper_prefers_publisher_when_canonical_is_non_article_utility_page(db_session_factory) -> None:
    seen: list[str] = []
    wrapper_html = """
    <html><head>
    <link rel="canonical" href="https://angular.dev/license">
    </head><body>
    <c-wiz data-n-au="https://publisher.test/threat-report"></c-wiz>
    </body></html>
    """
    transport = httpx.MockTransport(
        google_news_routes(
            {"/threat-report": ARTICLE_WITH_SECTION},
            wrapper_html=wrapper_html,
            seen=seen,
        )
    )
    agent = build_agent(google_news_settings(), transport, db_session_factory)
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    diagnostic = report.diagnostics[0]
    assert diagnostic.wrapper_resolved == 1
    assert diagnostic.pages_fetched == 1
    assert len(report.items) == 3
    assert all(item.reference_url == "https://publisher.test/threat-report" for item in report.items)
    assert not any("angular.dev/license" in url for url in seen)


@pytest.mark.asyncio
async def test_wrapper_can_fall_back_to_headless_browser_resolution(db_session_factory) -> None:
    seen: list[str] = []
    transport = httpx.MockTransport(
        google_news_routes(
            {"/threat-report": ARTICLE_WITH_SECTION},
            wrapper_html=GOOGLE_WRAPPER_ONLY_ASSETS,
            seen=seen,
        )
    )
    agent = build_agent(google_news_settings(), transport, db_session_factory)

    async def fake_browser_resolution(wrapper_url: str, *, timeout: float) -> str | None:
        assert wrapper_url.startswith("https://news.google.com/rss/articles/")
        assert timeout > 0
        return "https://publisher.test/threat-report"

    agent._resolve_google_news_article_via_browser = fake_browser_resolution  # type: ignore[method-assign]
    try:
        report = await agent.run_with_report()
    finally:
        await agent.http_client.aclose()

    diagnostic = report.diagnostics[0]
    assert diagnostic.wrapper_resolved == 1
    assert diagnostic.pages_fetched == 1
    assert len(report.items) == 3
    assert all(item.reference_url == "https://publisher.test/threat-report" for item in report.items)
    assert all(item.source == "discovery:publisher.test" for item in report.items)


@pytest.mark.asyncio
async def test_asset_candidate_url_is_discarded_before_fetch(db_session_factory) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path.endswith("blog.xml"):
            return httpx.Response(
                200,
                text=rss_feed(
                    [
                        {
                            "title": "Stealer IOC style asset link",
                            "link": "https://cdn.vendor.test/stealer-banner.png",
                        }
                    ]
                ),
            )
        return httpx.Response(404)

    agent = build_agent(build_settings(), httpx.MockTransport(handler), db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    assert diagnostic.skipped_non_article == 1
    assert diagnostic.pages_fetched == 0
    # Only the feed itself was requested; the .png was never fetched.
    assert all("stealer-banner.png" not in url for url in seen)


@pytest.mark.asyncio
async def test_fetched_shell_page_counts_as_empty_body_not_no_section(db_session_factory) -> None:
    shell = "<html><body><div id='app'>Loading…</div></body></html>"
    feed = [{"title": "Stealer IOC report", "link": "https://blog.vendor.test/shell"}]
    transport = httpx.MockTransport(routes(feed, {"/shell": shell}))
    agent = build_agent(build_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    assert diagnostic.skipped_empty_body == 1
    assert diagnostic.skipped_no_section == 0
    assert diagnostic.fetch_errors == 0


@pytest.mark.asyncio
async def test_weak_section_page_counts_as_weak(db_session_factory) -> None:
    weak_article = """
    <html><body>
    <h1>Campaign note</h1>
    <p>Short update on stealer phishing infrastructure this week with limited details.</p>
    <h2>Indicators of Compromise</h2>
    <ul><li>45.155.204.99</li></ul>
    </body></html>
    """
    feed = [{"title": "Stealer IOC note", "link": "https://blog.vendor.test/weak"}]
    transport = httpx.MockTransport(routes(feed, {"/weak": weak_article}))
    agent = build_agent(build_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    # One IOC < min_section_iocs=2 -> weak, not no_section, not empty_body.
    assert diagnostic.skipped_weak == 1
    assert diagnostic.skipped_no_section == 0
    assert diagnostic.skipped_empty_body == 0
    assert report.items == []


@pytest.mark.asyncio
async def test_discovery_skips_broad_directory_style_ioc_page(db_session_factory) -> None:
    broad_lines = "\n".join(
        [f"explorer-{index}.example.com" for index in range(45)]
    )
    broad_article = f"""
    <html><body>
    <h1>Wallet phishing roundup</h1>
    <h2>Indicators of Compromise</h2>
    <pre>{broad_lines}</pre>
    </body></html>
    """
    feed = [{"title": "Wallet phishing IOC roundup", "link": "https://blog.vendor.test/broad"}]
    transport = httpx.MockTransport(routes(feed, {"/broad": broad_article}))
    agent = build_agent(build_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    assert report.items == []
    assert diagnostic.skipped_weak == 1


@pytest.mark.asyncio
async def test_discovery_caps_legitimate_large_ioc_section_per_page(db_session_factory) -> None:
    hashes = "\n".join([f"{index:032x}"[-32:] for index in range(60)])
    large_article = f"""
    <html><body>
    <h1>Large malware appendix</h1>
    <h2>Indicators of Compromise</h2>
    <pre>{hashes}</pre>
    </body></html>
    """
    feed = [{"title": "Large malware IOC appendix", "link": "https://blog.vendor.test/large"}]
    transport = httpx.MockTransport(routes(feed, {"/large": large_article}))
    agent = build_agent(build_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    assert len(report.items) == 40
    assert all(item.attributes["extraction_mode"] == "ioc_section" for item in report.items)


@pytest.mark.asyncio
async def test_indicator_density_domain_cluster_does_not_count_as_ioc_section(db_session_factory) -> None:
    domain_cluster_article = """
    <html><body>
    <h1>What an orchid grower has learned from a phishing attack</h1>
    <p>The publisher network referenced a number of sister sites while discussing the incident.</p>
    <p>agf.nl</p>
    <p>freshplaza.es</p>
    <p>freshplaza.it</p>
    <p>freshplaza.de</p>
    <p>freshplaza.com</p>
    <p>freshplaza.fr</p>
    <p>freshplaza.cn</p>
    <p>hortidaily.com</p>
    <p>hortidaily.es</p>
    <p>verticalfarmdaily.com</p>
    </body></html>
    """
    feed = [{"title": "Publisher recap of phishing incident", "link": "https://blog.vendor.test/orchid"}]
    transport = httpx.MockTransport(routes(feed, {"/orchid": domain_cluster_article}))
    agent = build_agent(build_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    diagnostic = report.diagnostics[0]
    assert report.items == []
    assert diagnostic.skipped_no_section == 1
    assert diagnostic.skipped_weak == 0


@pytest.mark.asyncio
async def test_gbhackers_style_ioc_table_page_extracts(db_session_factory) -> None:
    table_article = """
    <html><body>
    <h1>New loader campaign delivers stealer</h1>
    <p>Researchers observed a loader delivering a credential stealer through
    malvertising. The infrastructure rotated quickly during the campaign and
    operators staged payloads behind newly registered domains before pivoting
    to compromised sites. Analysis of the delivery chain surfaced the network
    and file indicators listed below for defenders to action immediately.</p>
    <h2>IOCs</h2>
    <table>
      <tr><th>Type</th><th>Value</th></tr>
      <tr><td>Domain</td><td>loader-cdn[.]badcorp[.]top</td></tr>
      <tr><td>C2 IP</td><td>45.155.204.77</td></tr>
      <tr><td>URL</td><td>hxxps://drop[.]badcorp[.]top/stage2.bin</td></tr>
      <tr><td>SHA256</td><td>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</td></tr>
    </table>
    <h2>Conclusion</h2>
    <p>Block the listed infrastructure.</p>
    </body></html>
    """
    feed = [{"title": "Loader stealer campaign IOCs", "link": "https://blog.vendor.test/table"}]
    transport = httpx.MockTransport(routes(feed, {"/table": table_article}))
    agent = build_agent(build_settings(), transport, db_session_factory)

    report = await agent.run_with_report()

    values = {(item.type, item.value) for item in report.items}
    assert ("domain", "loader-cdn.badcorp.top") in values
    assert ("ipv4", "45.155.204.77") in values
    assert ("url", "https://drop.badcorp.top/stage2.bin") in values
    assert ("sha256", "a" * 64) in values
    assert all(item.attributes["extraction_mode"] == "ioc_section" for item in report.items)
    assert report.diagnostics[0].iocs_extracted >= 4


@pytest.mark.asyncio
async def test_fallback_extraction_is_labeled_fallback_not_ioc_section(db_session_factory) -> None:
    body = """
    <html><body>
    <h1>Phishing wave analysis</h1>
    <p>The campaign used hxxps://phish-kit[.]bad/login and hxxp://drop[.]bad/x plus
    C2 at 45.155.204.7 and more C2 at 45.155.204.8. This week the operators kept
    rotating hosting and continued targeting credential portals across several
    regions, expanding the lure set and refreshing their delivery domains while
    keeping the same distinctive kit fingerprints on every landing page we saw.</p>
    </body></html>
    """
    feed = [{"title": "Phishing IOC wave", "link": "https://blog.vendor.test/wave"}]
    transport = httpx.MockTransport(routes(feed, {"/wave": body}))
    settings = build_settings({"require_ioc_section": False})
    agent = build_agent(settings, transport, db_session_factory)

    report = await agent.run_with_report()

    assert report.items
    # Regression: fallback extractions must not be mislabeled as ioc_section,
    # or the extraction_mode memory surface learns from corrupted keys.
    assert all(item.attributes["extraction_mode"] == "fallback" for item in report.items)


@pytest.mark.asyncio
async def test_memory_sync_folds_feedback_and_informs_triage(db_session_factory) -> None:
    # Seed: two discovery sightings with feedback — one confirmed, one FP-heavy source.
    async with db_session_factory() as session:
        for index, (source, verdict) in enumerate(
            [
                ("discovery:good.vendor.test", "confirmed"),
                ("discovery:good.vendor.test", "confirmed"),
                ("discovery:noisy.vendor.test", "false_positive"),
                ("discovery:noisy.vendor.test", "false_positive"),
                ("discovery:noisy.vendor.test", "false_positive"),
            ]
        ):
            ioc = IOC(
                value=f"indicator-{index}.test",
                dedupe_hash=f"hash-{index}",
                type="domain",
                source=source,
                source_trust=0.6,
                first_seen=NOW,
                last_seen=NOW,
            )
            session.add(ioc)
            await session.flush()
            session.add(
                IOCSighting(
                    ioc_id=ioc.id,
                    source=source,
                    source_trust=0.6,
                    provenance="discovery",
                    reference_url=f"https://{source.removeprefix('discovery:')}/post-{index}",
                    first_seen=NOW,
                    last_seen=NOW,
                    lineage_hash=f"lineage-{index}",
                    attributes={
                        "search_profile": "test-profile",
                        "extraction_mode": "ioc_section",
                        "matched_keywords": ["stealer"],
                    },
                )
            )
            session.add(
                FeedbackRecord(
                    ioc_id=ioc.id,
                    analyst_id="analyst-1",
                    verdict=verdict,
                    timestamp=NOW,
                    channel="telegram",
                    source=source,
                )
            )
        await session.commit()

    store = DiscoveryMemoryStore(db_session_factory)
    written = await store.sync()
    assert written >= 3  # source x2, extraction_mode, keyword rows

    scores = await store.source_scores()
    host_scores = await store.publisher_host_scores()
    blocked_urls = await store.blocked_article_urls(min_false_positives=1)
    blocked_hosts = await store.blocked_publisher_hosts(min_false_positives=2, max_score=0.35)
    assert scores["discovery:good.vendor.test"] == pytest.approx(3 / 4)  # (2+1)/(2+2)
    assert scores["discovery:noisy.vendor.test"] == pytest.approx(1 / 5)  # (0+1)/(3+2)
    assert host_scores["good.vendor.test"] == pytest.approx(3 / 4)
    assert "https://noisy.vendor.test/post-2" in blocked_urls
    assert "noisy.vendor.test" in blocked_hosts

    # Sync is idempotent.
    await store.sync()
    async with db_session_factory() as session:
        rows = (await session.scalars(select(DiscoveryMemory))).all()
    by_key = {(row.kind, row.key): row for row in rows}
    assert by_key[("source", "discovery:noisy.vendor.test")].false_positive == 3
    assert by_key[("extraction_mode", "ioc_section")].confirmed == 2
    assert by_key[("keyword", "stealer")].confirmed == 2

    # The noisy source's memory score now drags its triage score below the
    # good source's for otherwise-identical candidates.
    feed_good = [{"title": "Stealer IOC report", "link": "https://good.vendor.test/post"}]
    transport = httpx.MockTransport(routes(feed_good, {}))
    settings = build_settings()
    agent = build_agent(settings, transport, db_session_factory)
    weights = agent.triage_weights()
    profile = settings.discovery.profiles[0]

    from sentinel.agents.scraper import RawWriteup

    def writeup(source: str) -> RawWriteup:
        return RawWriteup(
            source=source,
            source_trust=0.6,
            url=f"https://{source.removeprefix('discovery:')}/post",
            title="Stealer IOC report",
            published_at=NOW - timedelta(hours=1),
        )

    memory_scores = await store.source_scores()
    host_scores = await store.publisher_host_scores()
    good = agent._score_candidate(
        profile,
        writeup("discovery:good.vendor.test"),
        weights=weights,
        memory_scores=memory_scores,
        host_scores=host_scores,
    )
    noisy = agent._score_candidate(
        profile,
        writeup("discovery:noisy.vendor.test"),
        weights=weights,
        memory_scores=memory_scores,
        host_scores=host_scores,
    )
    assert good.score > noisy.score


@pytest.mark.asyncio
async def test_discovery_report_formatting(db_session_factory) -> None:
    feed = [{"title": "Stealer campaign IOCs", "link": "https://blog.vendor.test/stealer-campaign"}]
    transport = httpx.MockTransport(routes(feed, {"/stealer-campaign": ARTICLE_WITH_SECTION}))
    agent = build_agent(build_settings(), transport, db_session_factory)

    report = await agent.run_with_report()
    rendered = format_discovery_report(report)

    assert "profile=test-profile" in rendered
    assert "iocs=3" in rendered


@pytest.mark.asyncio
async def test_profile_name_filter_and_disabled_profiles(db_session_factory) -> None:
    transport = httpx.MockTransport(routes([], {}))
    settings = build_settings()
    agent = build_agent(settings, transport, db_session_factory)

    report = await agent.run_with_report(profile_names=["other-profile"])
    assert report.diagnostics == []

    settings.discovery.profiles[0].enabled = False
    report = await agent.run_with_report()
    assert report.diagnostics == []


def test_skill_knobs_are_parsed_from_skill_file(tmp_path: Path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text(
        "# Discovery Skill\n\n"
        "## Triage Weights\n- keyword_hits: 0.5\n- memory: 0.1\n\n"
        "## Gating\n- min_triage_score: 0.4\n\n"
        "## Section Signals\n- indicators of compromise\n- custom signal\n",
        encoding="utf-8",
    )
    settings = build_settings()
    agent = DiscoveryAgent(
        skill_path=str(skill),
        settings=settings,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(404))),
        session_factory=None,
    )
    weights = agent.triage_weights()
    assert weights["keyword_hits"] == 0.5
    assert weights["memory"] == 0.1
    assert weights["freshness"] == 0.15  # default preserved for unlisted keys
    assert agent.gating()["min_triage_score"] == 0.4
    assert "custom signal" in agent.section_signals()
