"""Bounded, analyst-style writeup discovery.

Additive layer on top of the existing feed/RSS ingestion: each configured
DiscoveryProfile searches its candidate feeds with keyword parameters, triages
candidates by likely signal density BEFORE fetching bodies, spends a strict
fetch/time budget on the best-ranked pages, prefers explicit IOC/indicator
sections, and skips weak pages quickly. High-fidelity results flow into the
normal pipeline (validation -> enrichment -> scoring -> delivery) tagged with
provenance="discovery" and full attribution, so analyst TP/FP feedback can be
folded back into a durable DiscoveryMemory table that future triage (and the
Karpathy loop, via skills/discovery/SKILL.md) uses to prefer what worked.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html import unescape
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import feedparser
import httpx
from sqlalchemy import select

from sentinel.agents.base import BaseAgent
from sentinel.agents.ioc_extract import (
    DEFAULT_SECTION_SIGNALS,
    _cell_indicator_token,
    extract_iocs_from_section,
    extract_iocs_from_text,
    find_ioc_section,
    html_to_text,
)
from sentinel.agents.scraper import RawIOC, RawWriteup, RSSAdapter
from sentinel.config import DiscoveryProfile, DiscoverySearchProvider, SentinelSettings, get_settings
from sentinel.db.models import DiscoveryMemory, FeedbackRecord, IOC, IOCSighting
from sentinel.feedback import (
    DISCOVERY_MEMORY_VERDICTS,
    FALSE_POSITIVE,
    LOW_LEVEL_TRUE_POSITIVE,
    NEEDS_REVIEW,
    normalize_verdict,
    positive_weight,
)


BLOCKED_DISCOVERY_HOSTS = {"otx.alienvault.com"}
SKILL_LINE_RE = re.compile(r"^- ([a-zA-Z0-9_ -]+?):\s*([0-9]*\.?[0-9]+)\s*$")
SKILL_SECTION_RE = re.compile(r"## (?P<name>[A-Za-z ]+)\n(?P<body>.*?)(?=\n## |\Z)", re.DOTALL)
SKILL_LIST_LINE_RE = re.compile(r"^- (.+?)\s*$")

# Sighting attribute keys that carry discovery attribution through to feedback.
ATTRIBUTION_KEYS = (
    "search_profile",
    "extraction_mode",
    "section_signal",
    "matched_keywords",
    "article_url",
    "triage_score",
)

DEFAULT_TRIAGE_WEIGHTS = {
    "keyword_hits": 0.35,
    "title_keyword_bonus": 0.20,
    "freshness": 0.15,
    "source_trust": 0.10,
    "memory": 0.20,
}
# min_triage_score must exceed the no-keyword baseline a fresh post from a
# neutral source earns from freshness+trust+memory alone (~0.30 with the
# default weights), or keyword-poor pages burn fetch budget.
# min_body_words only applies to pages where no IOC section was found: below
# it, a fetched page is classified as an empty shell (JS app, consent page)
# rather than a real article without indicators. Extraction always runs first,
# so an IOC-dense page can never be discarded as "thin".
DEFAULT_GATING = {
    "min_triage_score": 0.35,
    "min_section_iocs": 2.0,
    "min_fallback_iocs": 3.0,
    "min_body_words": 40.0,
    "max_broad_page_iocs": 40.0,
    "max_broad_page_unique_hosts": 25.0,
    "max_broad_page_strong_iocs": 2.0,
}

DEFAULT_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

HEADLESS_BROWSER_CANDIDATES = (
    "google-chrome",
    "chromium",
    "chromium-browser",
)
HEADLESS_BROWSER_VIRTUAL_TIME_MS = 8_000
HEADLESS_BROWSER_TIMEOUT_FLOOR_SECONDS = 45.0
GOOGLE_NEWS_BATCH_TIMEOUT_SECONDS = 8.0
GOOGLE_NEWS_BATCH_URL = "https://news.google.com/_/DotsSplashUi/data/batchexecute"

CANONICAL_LINK_RE = re.compile(
    r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\'](?P<url>[^"\']+)["\']',
    re.IGNORECASE,
)
OG_URL_RE = re.compile(
    r'<meta[^>]+property=["\']og:url["\'][^>]+content=["\'](?P<url>[^"\']+)["\']',
    re.IGNORECASE,
)
# Google News article wrappers annotate the publisher URL on elements.
DATA_ARTICLE_URL_RE = re.compile(
    r'data-n-au=["\'](?P<url>https?://[^"\']+)["\']',
    re.IGNORECASE,
)
DATA_P_RE = re.compile(r'<c-wiz[^>]+data-p=["\'](?P<data>[^"\']+)["\']', re.IGNORECASE)
DATA_N_A_ID_RE = re.compile(r'data-n-a-id=["\'](?P<id>[^"\']+)["\']', re.IGNORECASE)
DATA_N_A_TS_RE = re.compile(r'data-n-a-ts=["\'](?P<ts>\d+)["\']', re.IGNORECASE)
DATA_N_A_SG_RE = re.compile(r'data-n-a-sg=["\'](?P<signature>[^"\']+)["\']', re.IGNORECASE)
ANCHOR_HREF_RE = re.compile(
    r'<a[^>]+href=["\'](?P<url>https?://[^"\']+)["\']',
    re.IGNORECASE,
)
EMBEDDED_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)

# Hosts that never serve publisher articles: Google serving/infra, analytics,
# CDN asset domains, social-share endpoints, spec/vocabulary hosts.
NON_ARTICLE_HOST_SUFFIXES = (
    "googleusercontent.com",
    "gstatic.com",
    "news.google.com",
    "googleapis.com",  # fonts.googleapis.com etc. — seen in live wrapper pages
    "google.com",
    "googletagmanager.com",
    "google-analytics.com",
    "doubleclick.net",
    "youtube.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "linkedin.com",
    "schema.org",
    "w3.org",
)
NON_ARTICLE_EXTENSIONS = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".css",
    ".js",
    ".mjs",
    ".json",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".mp4",
    ".webm",
)
NON_ARTICLE_SINGLE_SEGMENT_PATHS = {
    "about",
    "contact",
    "cookies",
    "disclaimer",
    "license",
    "licenses",
    "privacy",
    "rss",
    "sitemap",
    "terms",
}


def is_generic_non_article_path(path: str) -> bool:
    """True for obvious site utility pages, not writeups."""
    segments = [segment for segment in path.lower().split("/") if segment]
    return len(segments) == 1 and segments[0] in NON_ARTICLE_SINGLE_SEGMENT_PATHS


def is_asset_url(url: str) -> bool:
    """File/asset/infra URLs that can never be a publisher writeup."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if not host:
        return True
    if any(path.endswith(ext) for ext in NON_ARTICLE_EXTENSIONS):
        return True
    asset_hosts = (
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "googletagmanager.com",
        "google-analytics.com",
        "doubleclick.net",
    )
    return any(host == suffix or host.endswith("." + suffix) for suffix in asset_hosts)


def is_article_like_url(url: str, *, base_host: str | None = None) -> bool:
    """True when a URL plausibly points at a publisher article page.

    Used when resolving news-aggregator wrappers: rejects asset URLs, Google
    serving infrastructure, social/analytics hosts, and root-only URLs (a
    publisher article always has a path).
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or parsed.scheme not in {"http", "https"}:
        return False
    if base_host and host == base_host.lower():
        return False
    if any(host == suffix or host.endswith("." + suffix) for suffix in NON_ARTICLE_HOST_SUFFIXES):
        return False
    if is_asset_url(url):
        return False
    if len(parsed.path.strip("/")) == 0:
        return False
    if is_generic_non_article_path(parsed.path):
        return False
    return True


class WrapperResolutionError(Exception):
    """A news-aggregator wrapper page exposed no valid publisher article URL."""


@dataclass(slots=True)
class Candidate:
    writeup: RawWriteup
    score: float
    matched_keywords: list[str]


@dataclass(slots=True)
class ProfileDiagnostic:
    profile: str
    candidates_seen: int = 0
    fresh: int = 0
    passed_triage: int = 0
    pages_fetched: int = 0
    skipped_low_score: int = 0
    skipped_denied_host: int = 0
    skipped_no_section: int = 0
    skipped_weak: int = 0
    skipped_budget: int = 0
    fetch_errors: int = 0
    iocs_extracted: int = 0
    # Candidate discarded because its URL (or all URLs a wrapper exposed)
    # were assets/wrappers, never a publisher article.
    skipped_non_article: int = 0
    # Page fetched fine but produced no meaningful readable article body.
    skipped_empty_body: int = 0
    # Wrapper candidates successfully resolved to a publisher article URL.
    wrapper_resolved: int = 0
    error: str | None = None


@dataclass(slots=True)
class DiscoveryReport:
    items: list[RawIOC]
    writeups: list[RawWriteup]
    diagnostics: list[ProfileDiagnostic] = field(default_factory=list)


class CandidateProvider:
    source_name: str

    async def fetch_writeups(self) -> list[RawWriteup]:
        raise NotImplementedError


def _parse_skill_numbers(skill_text: str, section: str, defaults: dict[str, float]) -> dict[str, float]:
    for match in SKILL_SECTION_RE.finditer(skill_text):
        if match.group("name").strip().lower() != section.lower():
            continue
        parsed = dict(defaults)
        for line in match.group("body").splitlines():
            entry = SKILL_LINE_RE.match(line.strip())
            if entry:
                parsed[entry.group(1).strip().lower().replace(" ", "_")] = float(entry.group(2))
        return parsed
    return dict(defaults)


def _parse_skill_list(skill_text: str, section: str, defaults: tuple[str, ...] | list[str]) -> list[str]:
    for match in SKILL_SECTION_RE.finditer(skill_text):
        if match.group("name").strip().lower() != section.lower():
            continue
        values = [
            entry.group(1).strip().lower()
            for line in match.group("body").splitlines()
            if (entry := SKILL_LIST_LINE_RE.match(line.strip()))
        ]
        return values or list(defaults)
    return list(defaults)


def _parse_discovery_datetime(value: str | None, *, fallback: datetime) -> datetime:
    if not value:
        return fallback
    raw = value.strip()
    for fmt in ("%Y%m%d%H%M%S", "%Y%m%dT%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return fallback


class GDELTSearchAdapter(CandidateProvider):
    source_name = "discovery:search:gdelt"

    def __init__(
        self,
        provider: DiscoverySearchProvider,
        *,
        profile: DiscoveryProfile,
        trust_score: float,
        client: httpx.AsyncClient,
        now_fn: Callable[[], datetime],
    ) -> None:
        self.provider = provider
        self.profile = profile
        self.trust_score = trust_score
        self.client = client
        self.now_fn = now_fn
        self.logger = logging.getLogger("DiscoveryAgent")

    def _query_terms(self) -> list[str]:
        terms = [term.strip() for term in self.provider.query_terms if term.strip()]
        if terms:
            return terms[: max(1, self.provider.max_queries)]
        return [term.strip() for term in self.profile.keywords if term.strip()][: max(1, self.provider.max_queries)]

    def _article_allowed(self, article: dict[str, Any]) -> bool:
        if self.provider.language:
            article_language = str(article.get("language") or "").strip().lower()
            if article_language and article_language != self.provider.language.strip().lower():
                return False
        if self.provider.source_country:
            article_country = str(article.get("sourcecountry") or "").strip().lower()
            if article_country and article_country != self.provider.source_country.strip().lower():
                return False
        return True

    def _request_params(self, term: str) -> dict[str, Any]:
        end = self.now_fn()
        start = end - timedelta(hours=max(1, self.profile.freshness_hours))
        query = f'"{term}"' if " " in term else term
        params: dict[str, Any] = {
            "query": query,
            "mode": "artlist",
            "format": "json",
            "maxrecords": max(1, self.provider.max_records),
            "sort": self.provider.sort,
            "startdatetime": start.strftime("%Y%m%d%H%M%S"),
            "enddatetime": end.strftime("%Y%m%d%H%M%S"),
        }
        return params

    def _decode_payload(self, response: httpx.Response, *, term: str) -> dict[str, Any] | None:
        try:
            payload = response.json()
            return payload if isinstance(payload, dict) else {}
        except ValueError:
            text = response.text.strip()
            if not text:
                self.logger.warning(
                    "Discovery search provider %s returned empty JSON body for term=%r.",
                    self.provider.name,
                    term,
                )
                return None
            for candidate in (text, text[text.find("{") : text.rfind("}") + 1] if "{" in text and "}" in text else ""):
                if not candidate:
                    continue
                try:
                    payload = json.loads(candidate)
                    return payload if isinstance(payload, dict) else {}
                except ValueError:
                    continue
            snippet = re.sub(r"\s+", " ", text[:180])
            self.logger.warning(
                "Discovery search provider %s returned malformed JSON for term=%r: %s",
                self.provider.name,
                term,
                snippet,
            )
            return None

    async def fetch_writeups(self) -> list[RawWriteup]:
        gathered: list[RawWriteup] = []
        seen_urls: set[str] = set()
        fallback_time = self.now_fn()
        for term in self._query_terms():
            try:
                response = await self.client.get(
                    self.provider.base_url,
                    params=self._request_params(term),
                    headers=DEFAULT_BROWSER_HEADERS,
                )
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status == 429:
                    self.logger.warning(
                        "Discovery search provider %s hit rate limiting on term=%r; keeping %s earlier result(s).",
                        self.provider.name,
                        term,
                        len(gathered),
                    )
                    break
                self.logger.warning(
                    "Discovery search provider %s query failed for term=%r: %s",
                    self.provider.name,
                    term,
                    status,
                )
                continue
            except httpx.HTTPError as exc:
                self.logger.warning(
                    "Discovery search provider %s query errored for term=%r: %s",
                    self.provider.name,
                    term,
                    type(exc).__name__,
                )
                continue
            payload = self._decode_payload(response, term=term)
            if payload is None:
                continue
            for article in payload.get("articles") or []:
                if not self._article_allowed(article):
                    continue
                url = str(article.get("url") or "").strip()
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                domain = str(article.get("domain") or urlparse(url).hostname or "unknown").lower()
                gathered.append(
                    RawWriteup(
                        source=f"discovery:{domain}",
                        source_trust=self.trust_score,
                        url=url,
                        title=article.get("title"),
                        published_at=_parse_discovery_datetime(article.get("seendate"), fallback=fallback_time),
                        summary=(
                            article.get("excerpt")
                            or article.get("description")
                            or article.get("title")
                        ),
                        tags=[],
                    )
                )
        return gathered


class GoogleNewsRSSSearchAdapter(CandidateProvider):
    source_name = "discovery:search:google-news-rss"

    def __init__(
        self,
        provider: DiscoverySearchProvider,
        *,
        profile: DiscoveryProfile,
        trust_score: float,
        client: httpx.AsyncClient,
        now_fn: Callable[[], datetime],
    ) -> None:
        self.provider = provider
        self.profile = profile
        self.trust_score = trust_score
        self.client = client
        self.now_fn = now_fn
        self.logger = logging.getLogger("DiscoveryAgent")

    def _query_terms(self) -> list[str]:
        terms = [term.strip() for term in self.provider.query_terms if term.strip()]
        if terms:
            return terms[: max(1, self.provider.max_queries)]
        return [term.strip() for term in self.profile.keywords if term.strip()][: max(1, self.provider.max_queries)]

    def _search_url(self, term: str) -> str:
        days = max(1, min(30, int((self.profile.freshness_hours + 23) // 24)))
        query = f'{term} when:{days}d'
        params = {
            "q": query,
            "hl": "en-US",
            "gl": "US",
            "ceid": "US:en",
        }
        return f"{self.provider.base_url}?{urlencode(params)}"

    async def fetch_writeups(self) -> list[RawWriteup]:
        gathered: list[RawWriteup] = []
        seen_urls: set[str] = set()
        for term in self._query_terms():
            try:
                response = await self.client.get(
                    self._search_url(term),
                    headers=DEFAULT_BROWSER_HEADERS,
                )
                response.raise_for_status()
            except httpx.HTTPError as exc:
                self.logger.warning(
                    "Discovery search provider %s query errored for term=%r: %s",
                    self.provider.name,
                    term,
                    type(exc).__name__,
                )
                continue
            parsed = feedparser.parse(response.text)
            for entry in parsed.entries[: max(1, self.provider.max_records)]:
                url = str(getattr(entry, "link", None) or entry.get("link") or "").strip()
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                published = getattr(entry, "published", None) or entry.get("published")
                title = getattr(entry, "title", None) or entry.get("title")
                summary = getattr(entry, "summary", None) or entry.get("summary")
                domain = str(urlparse(url).hostname or "unknown").lower()
                gathered.append(
                    RawWriteup(
                        source=f"discovery:{domain}",
                        source_trust=self.trust_score,
                        url=url,
                        title=title,
                        published_at=_parse_discovery_datetime(published, fallback=self.now_fn()),
                        summary=summary,
                        tags=[],
                    )
                )
        return gathered


class DiscoveryMemoryStore:
    """Durable TP/FP memory for discovery-derived alerts.

    sync() recomputes aggregates from analyst feedback joined to
    provenance="discovery" sightings — fully idempotent — and upserts one
    DiscoveryMemory row per (kind, key, profile). Kinds recorded:

    - source:          which discovery sources produce confirmed threats
    - keyword:         which matched search terms correlate with TP vs FP
    - extraction_mode: ioc_section vs fallback outcome quality

    Triage currently consumes source scores; keyword and extraction-mode rows
    are the measurable surface future Karpathy experiments can optimize.
    """

    def __init__(self, session_factory: Any) -> None:
        self.session_factory = session_factory

    async def _load_labeled_sightings(self, session: Any) -> list[dict[str, Any]]:
        query = (
            select(FeedbackRecord.verdict, IOCSighting.source, IOCSighting.attributes, IOCSighting.reference_url)
            .select_from(FeedbackRecord)
            .join(IOC, IOC.id == FeedbackRecord.ioc_id)
            .join(IOCSighting, IOCSighting.ioc_id == IOC.id)
            .where(IOCSighting.provenance.in_(["discovery", "writeup"]))
            .where(FeedbackRecord.verdict.in_(sorted(DISCOVERY_MEMORY_VERDICTS)))
        )
        rows = (await session.execute(query)).all()
        return [
            {
                "verdict": verdict,
                "source": source,
                "attributes": attributes or {},
                "reference_url": reference_url,
            }
            for verdict, source, attributes, reference_url in rows
        ]

    def _fold(self, rows: list[dict[str, Any]]) -> dict[tuple[str, str, str | None], dict[str, int]]:
        counts: dict[tuple[str, str, str | None], dict[str, int]] = {}

        def bump(kind: str, key: str, profile: str | None, verdict: str) -> None:
            bucket = counts.setdefault(
                (kind, key.lower(), profile),
                {
                    "confirmed": 0,
                    "low_level_true_positive": 0,
                    "false_positive": 0,
                    "needs_review": 0,
                    "positive_weight": 0.0,
                },
            )
            weight = positive_weight(verdict)
            if verdict == FALSE_POSITIVE:
                bucket["false_positive"] += 1
            elif verdict == NEEDS_REVIEW:
                bucket["needs_review"] += 1
            elif verdict == LOW_LEVEL_TRUE_POSITIVE:
                bucket["low_level_true_positive"] += 1
                bucket["confirmed"] += 1
                bucket["positive_weight"] += weight
            elif weight > 0.0:
                bucket["confirmed"] += 1
                bucket["positive_weight"] += weight

        for row in rows:
            verdict = normalize_verdict(row["verdict"])
            attributes = row["attributes"]
            profile = attributes.get("search_profile")
            bump("source", row["source"], profile, verdict)
            article_url = str(attributes.get("article_url") or row.get("reference_url") or "").strip()
            if article_url:
                bump("article_url", article_url, profile, verdict)
                publisher_host = (urlparse(article_url).hostname or "").lower()
                if publisher_host:
                    bump("publisher_host", publisher_host, profile, verdict)
            mode = attributes.get("extraction_mode")
            if mode:
                bump("extraction_mode", str(mode), profile, verdict)
            for keyword in attributes.get("matched_keywords") or []:
                bump("keyword", str(keyword), profile, verdict)
        return counts

    async def sync(self) -> int:
        """Recompute memory from feedback; returns number of rows written."""
        async with self.session_factory() as session:
            rows = await self._load_labeled_sightings(session)
            counts = self._fold(rows)
            written = 0
            for (kind, key, profile), bucket in counts.items():
                memory_hash = DiscoveryMemory.build_memory_hash(kind=kind, key=key, profile=profile)
                row = await session.scalar(
                    select(DiscoveryMemory).where(DiscoveryMemory.memory_hash == memory_hash)
                )
                if row is None:
                    row = DiscoveryMemory(kind=kind, key=key, profile=profile, memory_hash=memory_hash)
                    session.add(row)
                row.confirmed = bucket["confirmed"]
                row.false_positive = bucket["false_positive"]
                row.needs_review = bucket["needs_review"]
                row.score = DiscoveryMemory.laplace_score(bucket["positive_weight"], bucket["false_positive"])
                written += 1
            await session.commit()
            return written

    async def source_scores(self) -> dict[str, float]:
        """source key -> smoothed precision; missing sources default to 0.5."""
        async with self.session_factory() as session:
            rows = (
                await session.scalars(select(DiscoveryMemory).where(DiscoveryMemory.kind == "source"))
            ).all()
        return {row.key: row.score for row in rows}

    async def publisher_host_scores(self) -> dict[str, float]:
        async with self.session_factory() as session:
            rows = (
                await session.scalars(select(DiscoveryMemory).where(DiscoveryMemory.kind == "publisher_host"))
            ).all()
        return {row.key: row.score for row in rows}

    async def blocked_article_urls(
        self,
        *,
        min_false_positives: int,
    ) -> set[str]:
        async with self.session_factory() as session:
            rows = (
                await session.scalars(select(DiscoveryMemory).where(DiscoveryMemory.kind == "article_url"))
            ).all()
        return {
            row.key
            for row in rows
            if row.false_positive >= max(1, min_false_positives) and row.false_positive > row.confirmed
        }

    async def blocked_publisher_hosts(
        self,
        *,
        min_false_positives: int,
        max_score: float,
    ) -> set[str]:
        async with self.session_factory() as session:
            rows = (
                await session.scalars(select(DiscoveryMemory).where(DiscoveryMemory.kind == "publisher_host"))
            ).all()
        return {
            row.key
            for row in rows
            if row.false_positive >= max(1, min_false_positives) and row.false_positive > row.confirmed and row.score <= max_score
        }

    async def all_rows(self) -> list[DiscoveryMemory]:
        async with self.session_factory() as session:
            return list(
                (
                    await session.scalars(
                        select(DiscoveryMemory).order_by(DiscoveryMemory.kind, DiscoveryMemory.score.desc())
                    )
                ).all()
            )


def format_memory_rows(rows: list[DiscoveryMemory]) -> str:
    if not rows:
        return "Discovery memory is empty. Run the pipeline with discovery enabled and collect Telegram feedback first."
    lines = ["Discovery memory (Laplace-smoothed precision from analyst feedback):"]
    for row in rows:
        profile = row.profile or "*"
        lines.append(
            f"- kind={row.kind} key={row.key} profile={profile} score={row.score:.3f} "
            f"tp={row.confirmed} fp={row.false_positive} review={row.needs_review}"
        )
    return "\n".join(lines)


class DiscoveryAgent(BaseAgent):
    """Runs configured discovery profiles under strict budgets."""

    def __init__(
        self,
        skill_path: str = "skills/discovery/SKILL.md",
        *,
        settings: SentinelSettings | None = None,
        http_client: httpx.AsyncClient | None = None,
        session_factory: Any | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(skill_path)
        self.settings = settings or get_settings()
        timeout = float(self.settings.sources.http_timeout_seconds)
        self.http_client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=0),
        )
        self._owns_http_client = http_client is None
        if session_factory is None:
            from sentinel.db.session import AsyncSessionFactory

            self.session_factory = AsyncSessionFactory
        else:
            self.session_factory = session_factory
        self.memory = DiscoveryMemoryStore(self.session_factory)
        self.now_fn = now_fn or (lambda: datetime.now(UTC))
        self._logged_missing_headless_browser = False
        self.enable_browser_wrapper_resolution = (
            os.getenv("SENTINEL_DISCOVERY_BROWSER_WRAPPER_FALLBACK", "").strip().lower()
            in {"1", "true", "yes", "on"}
        )

    # -- skill knobs -----------------------------------------------------

    def triage_weights(self) -> dict[str, float]:
        return _parse_skill_numbers(self.skill_prompt, "Triage Weights", DEFAULT_TRIAGE_WEIGHTS)

    def gating(self) -> dict[str, float]:
        return _parse_skill_numbers(self.skill_prompt, "Gating", DEFAULT_GATING)

    def section_signals(self) -> list[str]:
        return _parse_skill_list(self.skill_prompt, "Section Signals", DEFAULT_SECTION_SIGNALS)

    # -- candidate gathering and triage -----------------------------------

    @staticmethod
    def _source_name_for(feed_url: str) -> str:
        host = (urlparse(feed_url).hostname or "unknown").lower()
        return f"discovery:{host}"

    @staticmethod
    def _host_matches(host: str, candidates: set[str]) -> bool:
        return any(host == candidate or host.endswith("." + candidate) for candidate in candidates)

    def _configured_feed_hosts(self) -> set[str]:
        return {
            host
            for feed in self.settings.sources.feeds
            if feed.enabled
            for host in [(urlparse(feed.url).hostname or "").lower()]
            if host
        }

    def _host_allowed(self, profile: DiscoveryProfile, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if host in BLOCKED_DISCOVERY_HOSTS:
            return False
        if self._host_matches(host, self._configured_feed_hosts()):
            return False
        if profile.deny_hosts and any(host == deny.lower() or host.endswith("." + deny.lower()) for deny in profile.deny_hosts):
            return False
        if profile.allow_hosts:
            return any(host == allow.lower() or host.endswith("." + allow.lower()) for allow in profile.allow_hosts)
        return True

    def _score_candidate(
        self,
        profile: DiscoveryProfile,
        writeup: RawWriteup,
        *,
        weights: dict[str, float],
        memory_scores: dict[str, float],
        host_scores: dict[str, float],
    ) -> Candidate:
        keywords = [keyword.strip().lower() for keyword in profile.keywords if keyword.strip()]
        title = (writeup.title or "").lower()
        haystack = "\n".join([title, (writeup.summary or "").lower(), " ".join(writeup.tags).lower()])
        matched = [keyword for keyword in keywords if keyword in haystack]
        keyword_component = len(matched) / len(keywords) if keywords else 0.0
        title_component = 1.0 if any(keyword in title for keyword in keywords) else 0.0
        age_hours = max((self.now_fn() - writeup.published_at).total_seconds() / 3600.0, 0.0)
        freshness_component = max(0.0, 1.0 - age_hours / max(profile.freshness_hours, 1))
        publisher_host = (urlparse(writeup.url).hostname or "").lower()
        source_memory = memory_scores.get(writeup.source, 0.5)
        host_memory = host_scores.get(publisher_host, 0.5)
        memory_component = (source_memory + host_memory) / 2.0
        score = (
            weights.get("keyword_hits", 0.0) * keyword_component
            + weights.get("title_keyword_bonus", 0.0) * title_component
            + weights.get("freshness", 0.0) * freshness_component
            + weights.get("source_trust", 0.0) * profile.source_trust
            + weights.get("memory", 0.0) * memory_component
        )
        return Candidate(writeup=writeup, score=round(score, 4), matched_keywords=matched)

    def _candidate_providers(self, profile: DiscoveryProfile) -> list[CandidateProvider]:
        providers: list[CandidateProvider] = [
            RSSAdapter(
                feed_url,
                trust_score=profile.source_trust,
                source_name=self._source_name_for(feed_url),
                client=self.http_client,
            )
            for feed_url in profile.feeds
            if (urlparse(feed_url).hostname or "").lower() not in BLOCKED_DISCOVERY_HOSTS
            and not self._host_matches((urlparse(feed_url).hostname or "").lower(), self._configured_feed_hosts())
        ]
        for search_provider in profile.search_providers:
            if not search_provider.enabled:
                continue
            if search_provider.provider == "gdelt_doc":
                providers.append(
                    GDELTSearchAdapter(
                        search_provider,
                        profile=profile,
                        trust_score=profile.source_trust,
                        client=self.http_client,
                        now_fn=self.now_fn,
                    )
                )
                continue
            if search_provider.provider == "google_news_rss":
                providers.append(
                    GoogleNewsRSSSearchAdapter(
                        search_provider,
                        profile=profile,
                        trust_score=profile.source_trust,
                        client=self.http_client,
                        now_fn=self.now_fn,
                    )
                )
                continue
            else:
                self.logger.warning(
                    "Discovery search provider %s uses unsupported provider=%s",
                    search_provider.name,
                    search_provider.provider,
                )
        return providers

    async def _gather_candidates(self, profile: DiscoveryProfile) -> list[RawWriteup]:
        adapters = self._candidate_providers(profile)
        timeout = float(self.settings.sources.http_timeout_seconds)
        results = await asyncio.gather(
            *(asyncio.wait_for(adapter.fetch_writeups(), timeout=timeout) for adapter in adapters),
            return_exceptions=True,
        )
        gathered: list[RawWriteup] = []
        seen_urls: set[str] = set()
        for adapter, result in zip(adapters, results, strict=True):
            if isinstance(result, Exception):
                self.logger.warning(
                    "Discovery candidate fetch failed for %s: %s", adapter.source_name, type(result).__name__
                )
                continue
            for writeup in result[: profile.max_candidates_per_source]:
                if writeup.url not in seen_urls:
                    seen_urls.add(writeup.url)
                    gathered.append(writeup)
        return gathered

    # -- page processing ---------------------------------------------------

    @staticmethod
    def _request_headers(url: str) -> dict[str, str]:
        parsed = urlparse(url)
        headers = dict(DEFAULT_BROWSER_HEADERS)
        if parsed.scheme and parsed.netloc:
            headers["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"
        return headers

    @staticmethod
    def _summary_text(writeup: RawWriteup) -> str:
        if not writeup.summary:
            return ""
        return html_to_text(writeup.summary)[:50_000]

    @staticmethod
    def _extract_canonical_article_url(html: str, *, base_url: str) -> str | None:
        """Best publisher-article URL exposed by a wrapper page, or None.

        Candidates are considered in confidence tiers — canonical/og metadata,
        Google's data-n-au annotations, anchor hrefs, then the raw embedded-URL
        soup — and every candidate must pass the article-likeness classifier,
        so font/CSS/image/infra URLs can never win no matter the tier.
        """
        decoded_html = unescape(html)
        tiers: list[list[str]] = [[], [], [], []]
        for pattern in (CANONICAL_LINK_RE, OG_URL_RE):
            match = pattern.search(html)
            if match:
                tiers[0].append(match.group("url").strip())
        tiers[1].extend(match.group("url") for match in DATA_ARTICLE_URL_RE.finditer(decoded_html))
        tiers[2].extend(match.group("url") for match in ANCHOR_HREF_RE.finditer(decoded_html))
        tiers[3].extend(EMBEDDED_URL_RE.findall(decoded_html))
        base_host = urlparse(base_url).hostname
        for tier in tiers:
            for candidate in tier:
                resolved = urljoin(base_url, candidate.strip())
                if is_article_like_url(resolved, base_host=base_host):
                    return resolved
                # Redirector links (`...?url=https://publisher/...`) count too.
                query_url = parse_qs(urlparse(resolved).query).get("url", [])
                if query_url and is_article_like_url(query_url[0], base_host=base_host):
                    return query_url[0]
        return None

    @staticmethod
    def _google_news_article_id(url: str) -> str | None:
        parsed = urlparse(url)
        if (parsed.hostname or "").lower() != "news.google.com":
            return None
        segments = [segment for segment in parsed.path.split("/") if segment]
        if len(segments) >= 2 and segments[-2] == "articles":
            return segments[-1]
        return None

    @staticmethod
    def _google_news_signature_request(html: str, *, wrapper_url: str) -> list[Any] | None:
        decoded_html = unescape(html)
        article_id = None
        if match := DATA_N_A_ID_RE.search(decoded_html):
            article_id = match.group("id").strip()
        article_id = article_id or DiscoveryAgent._google_news_article_id(wrapper_url)
        ts_match = DATA_N_A_TS_RE.search(decoded_html)
        sig_match = DATA_N_A_SG_RE.search(decoded_html)
        if not article_id or not ts_match or not sig_match:
            return None
        try:
            timestamp = int(ts_match.group("ts"))
        except ValueError:
            return None
        signature = sig_match.group("signature").strip()
        if not signature:
            return None
        return [
            "garturlreq",
            [
                [
                    "en-US",
                    "US",
                    ["FINANCE_TOP_INDICES", "WEB_TEST_1_0_0"],
                    None,
                    None,
                    1,
                    1,
                    "US:en",
                    None,
                    180,
                    None,
                    None,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    [1608992183, 723341000],
                ],
                "en-US",
                "US",
                1,
                [2, 3, 4, 8],
                1,
                0,
                "655000234",
                0,
                0,
                None,
                0,
            ],
            article_id,
            timestamp,
            signature,
        ]

    @staticmethod
    def _google_news_data_p_request(html: str) -> list[Any] | None:
        match = DATA_P_RE.search(html)
        if not match:
            return None
        raw = unescape(match.group("data")).replace("%.@.", '["garturlreq",')
        try:
            parsed = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(parsed, list):
            return None
        # Google's page includes trailing UI-only fields; the RPC wants the
        # garturl request body plus the final article id/signature parameters.
        if len(parsed) > 6:
            parsed = [*parsed[:-6], *parsed[-2:]]
        return parsed

    @staticmethod
    def _extract_batchexecute_article_url(text: str, *, base_url: str) -> str | None:
        cleaned = text.strip()
        if cleaned.startswith(")]}'"):
            cleaned = cleaned[4:].strip()
        try:
            payload = json.loads(cleaned)
        except ValueError:
            return None
        base_host = urlparse(base_url).hostname

        def walk(value: Any) -> str | None:
            if isinstance(value, str):
                stripped = value.strip()
                if stripped.startswith(("[", "{")):
                    try:
                        nested = json.loads(stripped)
                    except ValueError:
                        nested = None
                    if nested is not None and (found := walk(nested)):
                        return found
                if stripped.startswith("http") and is_article_like_url(stripped, base_host=base_host):
                    return stripped
                return None
            if isinstance(value, dict):
                for nested in value.values():
                    if found := walk(nested):
                        return found
            if isinstance(value, list):
                for nested in value:
                    if found := walk(nested):
                        return found
            return None

        return walk(payload)

    async def _resolve_google_news_article_via_batch(self, wrapper_url: str, html: str, *, timeout: float) -> str | None:
        requests = [
            request
            for request in (
                self._google_news_data_p_request(html),
                self._google_news_signature_request(html, wrapper_url=wrapper_url),
            )
            if request is not None
        ]
        if not requests:
            return None
        request_timeout = min(max(float(timeout), 1.0), GOOGLE_NEWS_BATCH_TIMEOUT_SECONDS)
        headers = {
            **DEFAULT_BROWSER_HEADERS,
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Referer": wrapper_url,
        }
        for request in requests:
            rpc = [[["Fbv4je", json.dumps(request, separators=(",", ":")), None, "generic"]]]
            try:
                response = await asyncio.wait_for(
                    self.http_client.post(
                        GOOGLE_NEWS_BATCH_URL,
                        headers=headers,
                        data={"f.req": json.dumps(rpc, separators=(",", ":"))},
                    ),
                    timeout=request_timeout,
                )
                response.raise_for_status()
            except httpx.HTTPError as exc:
                self.logger.info(
                    "Discovery Google News batch resolver failed for wrapper url=%s: %s",
                    wrapper_url,
                    type(exc).__name__,
                )
                continue
            except TimeoutError:
                self.logger.info(
                    "Discovery Google News batch resolver timed out after %.0fs for wrapper url=%s",
                    request_timeout,
                    wrapper_url,
                )
                continue
            if article_url := self._extract_batchexecute_article_url(response.text, base_url=wrapper_url):
                return article_url
        return None

    @staticmethod
    def _headless_browser_binary() -> str | None:
        for candidate in HEADLESS_BROWSER_CANDIDATES:
            path = shutil.which(candidate)
            if path:
                return path
        return None

    async def _resolve_google_news_article_via_browser(self, wrapper_url: str, *, timeout: float) -> str | None:
        browser = self._headless_browser_binary()
        if not browser:
            if not self._logged_missing_headless_browser:
                self.logger.warning(
                    "Discovery cannot resolve Google News wrappers because no headless browser binary was found. "
                    "Install one of: %s.",
                    ", ".join(HEADLESS_BROWSER_CANDIDATES),
                )
                self._logged_missing_headless_browser = True
            return None
        try:
            with tempfile.TemporaryDirectory(prefix="sentinel-chromium-") as user_data_dir:
                process = await asyncio.create_subprocess_exec(
                    browser,
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--no-first-run",
                    "--no-default-browser-check",
                    f"--user-data-dir={user_data_dir}",
                    f"--virtual-time-budget={HEADLESS_BROWSER_VIRTUAL_TIME_MS}",
                    "--dump-dom",
                    wrapper_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                process_timeout = max(float(timeout), HEADLESS_BROWSER_TIMEOUT_FLOOR_SECONDS)
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=process_timeout)
                except TimeoutError:
                    process.kill()
                    await process.communicate()
                    self.logger.warning(
                        "Discovery headless browser timed out after %.0fs while resolving wrapper url=%s",
                        process_timeout,
                        wrapper_url,
                    )
                    return None
        except OSError as exc:
            self.logger.warning(
                "Discovery could not start headless browser for wrapper resolution with binary=%s: %s",
                browser,
                exc,
            )
            return None
        if process.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            if stderr_text:
                self.logger.warning(
                    "Discovery headless browser failed while resolving wrapper url=%s: %s",
                    wrapper_url,
                    stderr_text[:500],
                )
            return None
        rendered_html = stdout.decode("utf-8", errors="replace")
        return self._extract_canonical_article_url(rendered_html, base_url=wrapper_url)

    async def _resolve_google_news_article(self, writeup: RawWriteup, response: httpx.Response, *, timeout: float) -> httpx.Response:
        original_url = writeup.url
        canonical_url = self._extract_canonical_article_url(response.text, base_url=str(response.url))
        if not canonical_url:
            canonical_url = await self._resolve_google_news_article_via_batch(
                str(response.url),
                response.text,
                timeout=timeout,
            )
        if not canonical_url:
            if self.enable_browser_wrapper_resolution:
                canonical_url = await self._resolve_google_news_article_via_browser(
                    str(response.url), timeout=timeout
                )
            else:
                self.logger.info(
                    "Discovery skipped headless browser fallback for Google News wrapper; "
                    "set SENTINEL_DISCOVERY_BROWSER_WRAPPER_FALLBACK=1 to enable it."
                )
        if not canonical_url:
            self.logger.warning(
                "Discovery discarded wrapper candidate: no publisher article URL found "
                "(only wrapper/asset URLs) original=%s",
                original_url,
            )
            raise WrapperResolutionError("Google News wrapper exposed only wrapper/asset URLs.")
        self.logger.info(
            "Discovery resolved wrapper original=%s -> article=%s", original_url, canonical_url
        )
        writeup.url = canonical_url
        publisher_host = (urlparse(canonical_url).hostname or "").lower()
        if publisher_host:
            writeup.source = f"discovery:{publisher_host}"
        return await asyncio.wait_for(
            self.http_client.get(canonical_url, headers=self._request_headers(canonical_url)),
            timeout=timeout,
        )

    def _extract_candidate_items(
        self,
        profile: DiscoveryProfile,
        candidate: Candidate,
        text: str,
        *,
        origin: str,
    ) -> tuple[list[RawIOC], str | None, str | None]:
        """Extract from page or summary text. origin is "page" or "summary".

        extraction_mode on emitted items stays one of the three stable memory
        keys: "ioc_section" (section found on a page), "fallback" (whole-body
        page extraction), "feed_summary" (anything from the RSS summary).
        """
        gating = self.gating()
        writeup = candidate.writeup
        own_host = (urlparse(writeup.url).hostname or "").lower()
        exclude = {own_host} if own_host else set()
        section = find_ioc_section(text, signals=self.section_signals())
        if section is not None:
            extracted = extract_iocs_from_section(section.text, exclude_hostnames=exclude)
            if self._looks_like_broad_directory_page(extracted, gating=gating):
                return [], section.signal, "weak"
            extracted = extracted[: max(0, int(profile.max_iocs_per_page_ioc_section))]
            if len(extracted) >= gating["min_section_iocs"]:
                return (
                    self._build_items(
                        profile,
                        candidate,
                        extracted,
                        extraction_mode="ioc_section" if origin == "page" else "feed_summary",
                        section_signal=section.signal,
                    ),
                    section.signal,
                    None,
                )
            return [], section.signal, "weak"
        if profile.require_ioc_section:
            return [], None, "no_section"
        fallback = extract_iocs_from_text(
            "\n".join([writeup.title or "", writeup.summary or "", text]),
            exclude_hostnames=exclude,
        )
        if self._looks_like_broad_directory_page(fallback, gating=gating):
            return [], None, "weak"
        fallback = fallback[: max(0, int(profile.max_iocs_per_page_fallback))]
        if len(fallback) >= gating["min_fallback_iocs"]:
            return (
                self._build_items(
                    profile,
                    candidate,
                    fallback,
                    extraction_mode="fallback" if origin == "page" else "feed_summary",
                    section_signal=None,
                ),
                None,
                None,
            )
        return [], None, "weak"

    @staticmethod
    def _entry_hostname(entry: Any) -> str | None:
        value = str(getattr(entry, "value", "") or "").strip().lower()
        entry_type = str(getattr(entry, "type", "") or "").strip().lower()
        if entry_type == "url":
            return (urlparse(value).hostname or "").lower() or None
        if entry_type == "domain":
            return value or None
        return None

    def _looks_like_broad_directory_page(self, extracted: list[Any], *, gating: dict[str, float]) -> bool:
        if not extracted:
            return False
        max_page_iocs = int(gating.get("max_broad_page_iocs", DEFAULT_GATING["max_broad_page_iocs"]))
        if len(extracted) < max_page_iocs:
            return False
        networkish = [entry for entry in extracted if str(getattr(entry, "type", "")).lower() in {"domain", "url"}]
        if len(networkish) / len(extracted) < 0.85:
            return False
        unique_hosts = {
            host
            for host in (self._entry_hostname(entry) for entry in extracted)
            if host
        }
        strong_types = {"ipv4", "ipv6", "md5", "sha1", "sha256", "cve"}
        strong_count = sum(1 for entry in extracted if str(getattr(entry, "type", "")).lower() in strong_types)
        return (
            len(unique_hosts) >= int(gating.get("max_broad_page_unique_hosts", DEFAULT_GATING["max_broad_page_unique_hosts"]))
            and strong_count <= int(gating.get("max_broad_page_strong_iocs", DEFAULT_GATING["max_broad_page_strong_iocs"]))
        )

    # fetch_error marker prefixes _run_profile branches on for diagnostics.
    NON_ARTICLE_MARKER = "non_article:"
    EMPTY_BODY_MARKER = "empty_body:"

    async def _fetch_body(self, writeup: RawWriteup, *, timeout: float) -> None:
        try:
            original_host = (urlparse(writeup.url).hostname or "").lower()
            response = await asyncio.wait_for(
                self.http_client.get(writeup.url, headers=self._request_headers(writeup.url)),
                timeout=timeout,
            )
            response.raise_for_status()
            # httpx.URL exposes .host (not urllib's .hostname) — keep it that way.
            response_host = (response.url.host or "").lower()
            if original_host == "news.google.com" or response_host == "news.google.com":
                response = await self._resolve_google_news_article(writeup, response, timeout=timeout)
                response.raise_for_status()
            raw_html = response.text[:1_500_000]
            content_text = html_to_text(raw_html)[:200_000]
            if not content_text.strip():
                # Some wrappers and JS-heavy pages yield almost no parser text;
                # keep a crude tag-stripped fallback so extraction can still try.
                content_text = re.sub(r"<[^>]+>", " ", raw_html)
                content_text = re.sub(r"\s+", " ", unescape(content_text)).strip()[:200_000]
            if not content_text:
                writeup.fetch_error = f"{self.EMPTY_BODY_MARKER} fetched page produced no readable text"
                return
            writeup.content_text = content_text
        except WrapperResolutionError as exc:
            writeup.fetch_error = f"{self.NON_ARTICLE_MARKER} {exc}"
        except Exception as exc:
            writeup.fetch_error = f"{type(exc).__name__}: {exc}"

    def _build_items(
        self,
        profile: DiscoveryProfile,
        candidate: Candidate,
        extracted: list,
        *,
        extraction_mode: str,
        section_signal: str | None,
    ) -> list[RawIOC]:
        writeup = candidate.writeup
        items: list[RawIOC] = []
        for entry in extracted:
            items.append(
                RawIOC(
                    value=entry.value,
                    type=entry.type,
                    source=writeup.source,
                    source_trust=profile.source_trust,
                    first_seen=writeup.published_at,
                    last_seen=writeup.published_at,
                    tags=list(writeup.tags),
                    description=writeup.title,
                    reference_url=writeup.url,
                    attributes={
                        "article_title": writeup.title,
                        "article_url": writeup.url,
                        "extraction": "discovery-v1",
                        "search_profile": profile.name,
                        "extraction_mode": extraction_mode,
                        "section_signal": section_signal,
                        "ioc_section_label": getattr(entry, "section_label", None),
                        "matched_keywords": candidate.matched_keywords,
                        "triage_score": candidate.score,
                    },
                    provenance="discovery",
                )
            )
        return items

    async def _run_profile(self, profile: DiscoveryProfile) -> tuple[list[RawIOC], list[RawWriteup], ProfileDiagnostic]:
        diagnostic = ProfileDiagnostic(profile=profile.name)
        weights = self.triage_weights()
        gating = self.gating()
        signals = self.section_signals()
        try:
            memory_scores = await self.memory.source_scores()
            host_scores = await self.memory.publisher_host_scores()
            blocked_urls = await self.memory.blocked_article_urls(
                min_false_positives=self.settings.discovery.blocked_article_false_positive_threshold
            )
            blocked_hosts = await self.memory.blocked_publisher_hosts(
                min_false_positives=self.settings.discovery.blocked_host_false_positive_threshold,
                max_score=float(self.settings.discovery.blocked_host_max_score),
            )
        except Exception as exc:
            self.logger.info("Discovery memory unavailable (%s); using neutral triage memory.", type(exc).__name__)
            memory_scores = {}
            host_scores = {}
            blocked_urls = set()
            blocked_hosts = set()

        candidates_raw = await self._gather_candidates(profile)
        diagnostic.candidates_seen = len(candidates_raw)
        cutoff = self.now_fn() - timedelta(hours=profile.freshness_hours)
        fresh = [writeup for writeup in candidates_raw if writeup.published_at >= cutoff]
        diagnostic.fresh = len(fresh)

        scored: list[Candidate] = []
        for writeup in fresh:
            if not self._host_allowed(profile, writeup.url):
                diagnostic.skipped_denied_host += 1
                continue
            article_url = str(writeup.url or "").strip().lower()
            publisher_host = (urlparse(writeup.url).hostname or "").lower()
            if article_url in blocked_urls or (publisher_host and publisher_host in blocked_hosts):
                diagnostic.skipped_denied_host += 1
                continue
            candidate = self._score_candidate(
                profile,
                writeup,
                weights=weights,
                memory_scores=memory_scores,
                host_scores=host_scores,
            )
            if candidate.score < gating["min_triage_score"]:
                diagnostic.skipped_low_score += 1
                continue
            scored.append(candidate)
        scored.sort(key=lambda candidate: candidate.score, reverse=True)
        ranked = scored[: profile.max_pages_per_run]
        diagnostic.passed_triage = len(ranked)

        gating_values = gating
        min_body_words = int(gating_values.get("min_body_words", DEFAULT_GATING["min_body_words"]))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(1, profile.time_budget_seconds)
        items: list[RawIOC] = []
        processed_writeups: list[RawWriteup] = []
        for candidate in ranked:
            remaining = deadline - loop.time()
            if remaining <= 0:
                diagnostic.skipped_budget += 1
                continue
            writeup = candidate.writeup
            if is_asset_url(writeup.url):
                diagnostic.skipped_non_article += 1
                self.logger.warning(
                    "Discovery discarded asset/non-article candidate before fetch: profile=%s url=%s",
                    profile.name,
                    writeup.url,
                )
                continue
            original_url = writeup.url
            self.logger.info("Discovery fetching profile=%s url=%s", profile.name, writeup.url)
            await self._fetch_body(writeup, timeout=min(profile.per_page_timeout_seconds, remaining))

            if writeup.fetch_error and writeup.fetch_error.startswith(self.NON_ARTICLE_MARKER):
                # Wrapper exposed only asset/wrapper URLs; discard cleanly and
                # spend no extraction effort (its summary is link soup anyway).
                diagnostic.skipped_non_article += 1
                continue
            if writeup.fetch_error and writeup.fetch_error.startswith(self.EMPTY_BODY_MARKER):
                diagnostic.skipped_empty_body += 1
                self.logger.warning(
                    "Discovery fetched page but found no readable article body: profile=%s url=%s",
                    profile.name,
                    writeup.url,
                )
                continue
            if writeup.fetch_error or not writeup.content_text:
                diagnostic.fetch_errors += 1
                self.logger.warning(
                    "Discovery fetch failed for profile=%s url=%s error=%s",
                    profile.name,
                    writeup.url,
                    writeup.fetch_error or "no content",
                )
                summary_text = self._summary_text(writeup)
                if not summary_text:
                    continue
                extracted_items, _, _ = self._extract_candidate_items(
                    profile,
                    candidate,
                    summary_text,
                    origin="summary",
                )
                if extracted_items:
                    processed_writeups.append(writeup)
                    items.extend(extracted_items)
                    diagnostic.iocs_extracted += len(extracted_items)
                    self.logger.info(
                        "Discovery extracted %s IOC(s) from RSS summary after fetch failure for %s",
                        len(extracted_items),
                        writeup.url,
                    )
                continue

            if writeup.url != original_url:
                diagnostic.wrapper_resolved += 1
                # Profile allow/deny policy applies to the publisher, not the wrapper.
                if not self._host_allowed(profile, writeup.url):
                    diagnostic.skipped_denied_host += 1
                    self.logger.info(
                        "Discovery resolved article host is denied by profile=%s url=%s",
                        profile.name,
                        writeup.url,
                    )
                    continue
            diagnostic.pages_fetched += 1
            processed_writeups.append(writeup)

            extracted_items, _, failure_reason = self._extract_candidate_items(
                profile,
                candidate,
                writeup.content_text,
                origin="page",
            )
            if extracted_items:
                items.extend(extracted_items)
                diagnostic.iocs_extracted += len(extracted_items)
                continue
            body_words = len(writeup.content_text.split())
            if failure_reason == "no_section" and body_words < min_body_words:
                has_indicator_like_lines = any(_cell_indicator_token(line) is not None for line in writeup.content_text.splitlines())
                if has_indicator_like_lines:
                    diagnostic.skipped_no_section += 1
                    self.logger.info(
                        "Discovery page had no IOC section despite indicator-like lines: profile=%s url=%s",
                        profile.name,
                        writeup.url,
                    )
                    continue
                # Fetched fine but there is no real article here (JS shell,
                # consent page, boilerplate): distinct from a genuine article
                # that simply lacks an IOC section.
                diagnostic.skipped_empty_body += 1
                self.logger.warning(
                    "Discovery page has no meaningful readable body (%s words): profile=%s url=%s",
                    body_words,
                    profile.name,
                    writeup.url,
                )
            elif failure_reason == "no_section":
                diagnostic.skipped_no_section += 1
                self.logger.info(
                    "Discovery page had no IOC section: profile=%s url=%s", profile.name, writeup.url
                )
            else:
                diagnostic.skipped_weak += 1
                self.logger.info(
                    "Discovery page had a weak IOC yield: profile=%s url=%s", profile.name, writeup.url
                )
        return items, processed_writeups, diagnostic

    async def run_with_report(self, *, profile_names: list[str] | None = None) -> DiscoveryReport:
        self.reload_skill()
        wanted = {name.lower() for name in profile_names} if profile_names else None
        report = DiscoveryReport(items=[], writeups=[])
        for profile in self.settings.discovery.profiles:
            if not profile.enabled:
                continue
            if wanted is not None and profile.name.lower() not in wanted:
                continue
            try:
                items, writeups, diagnostic = await self._run_profile(profile)
            except Exception as exc:
                self.logger.exception("Discovery profile %s failed", profile.name, exc_info=exc)
                report.diagnostics.append(ProfileDiagnostic(profile=profile.name, error=f"{type(exc).__name__}: {exc}"))
                continue
            report.items.extend(items)
            report.writeups.extend(writeups)
            report.diagnostics.append(diagnostic)
            self.logger.info(
                "Discovery profile=%s candidates=%s fresh=%s triaged=%s fetched=%s extracted=%s "
                "wrapper_resolved=%s skipped(no_section=%s weak=%s low_score=%s budget=%s "
                "non_article=%s empty_body=%s) fetch_errors=%s",
                profile.name,
                diagnostic.candidates_seen,
                diagnostic.fresh,
                diagnostic.passed_triage,
                diagnostic.pages_fetched,
                diagnostic.iocs_extracted,
                diagnostic.wrapper_resolved,
                diagnostic.skipped_no_section,
                diagnostic.skipped_weak,
                diagnostic.skipped_low_score,
                diagnostic.skipped_budget,
                diagnostic.skipped_non_article,
                diagnostic.skipped_empty_body,
                diagnostic.fetch_errors,
            )
        return report

    async def run(self, *args: Any, **kwargs: Any) -> list[RawIOC]:
        report = await self.run_with_report(**kwargs)
        return report.items

    async def aclose(self) -> None:
        if self._owns_http_client:
            try:
                await asyncio.wait_for(self.http_client.aclose(), timeout=5.0)
            except TimeoutError:
                self.logger.warning("Timed out while closing discovery HTTP client; continuing shutdown.")


def format_discovery_report(report: DiscoveryReport) -> str:
    lines = [f"Discovery run: extracted={len(report.items)} writeups_fetched={len(report.writeups)}"]
    for diagnostic in report.diagnostics:
        if diagnostic.error:
            lines.append(f"- profile={diagnostic.profile} error={diagnostic.error}")
            continue
        lines.append(
            f"- profile={diagnostic.profile} candidates={diagnostic.candidates_seen} fresh={diagnostic.fresh} "
            f"triaged={diagnostic.passed_triage} fetched={diagnostic.pages_fetched} iocs={diagnostic.iocs_extracted} "
            f"wrapper_resolved={diagnostic.wrapper_resolved} "
            f"skipped: low_score={diagnostic.skipped_low_score} denied={diagnostic.skipped_denied_host} "
            f"no_section={diagnostic.skipped_no_section} weak={diagnostic.skipped_weak} "
            f"budget={diagnostic.skipped_budget} non_article={diagnostic.skipped_non_article} "
            f"empty_body={diagnostic.skipped_empty_body} fetch_errors={diagnostic.fetch_errors}"
        )
    for item in report.items[:10]:
        lines.append(f"  extracted: {item.type}={item.value} mode={item.attributes.get('extraction_mode')} from={item.reference_url}")
    if len(report.items) > 10:
        lines.append(f"  ... and {len(report.items) - 10} more")
    return "\n".join(lines)
