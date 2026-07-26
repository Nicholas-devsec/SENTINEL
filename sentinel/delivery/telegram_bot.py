from __future__ import annotations

import html as html_module
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any
from urllib.parse import urlparse

from telegram import Bot, Chat, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, ContextTypes

from sentinel.agents.ioc_extract import refang


MAX_TELEGRAM_MESSAGE_CHARS = 3500
MAX_DIGEST_LINKS_PER_ITEM = 2
MAX_SOURCE_TITLE_CHARS = 90
MAX_IOC_VALUE_CHARS = 120
MAX_LINK_CHARS = 140
MAX_GROUPED_IOCS = 5
ARTICLE_IOC_NOTE_THRESHOLD = 5
TELEGRAM_PARSE_MODE = "HTML"
OTX_HOST = "otx.alienvault.com"

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "🔵",
}

# Human-readable labels for score_breakdown components, in display priority.
SCORE_COMPONENT_LABELS = {
    "context": "article context",
    "corroboration": "corroboration",
    "vt_ratio": "VirusTotal",
    "abuse_confidence": "AbuseIPDB",
    "source_trust": "source trust",
    "recency": "recency",
}


@dataclass(slots=True)
class TelegramChatCandidate:
    chat_id: str
    chat_type: str
    title: str | None
    username: str | None
    update_type: str


def build_feedback_markup(ioc_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("True Positive", callback_data=f"confirmed:{ioc_id}"),
                InlineKeyboardButton("Low-level True Positive", callback_data=f"low_level_true_positive:{ioc_id}"),
            ],
            [
                InlineKeyboardButton("False Positive", callback_data=f"false_positive:{ioc_id}"),
                InlineKeyboardButton("Needs Review", callback_data=f"needs_review:{ioc_id}"),
            ],
        ]
    )


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _escape(text: str) -> str:
    return html_module.escape(str(text), quote=True)


def defang(value: str, ioc_type: str) -> str:
    """Render an indicator so chat clients cannot auto-link or auto-fetch it.

    Alerts must never contain live malicious hyperlinks: an accidental tap on
    a C2 URL from a phone is a real incident. Hashes and CVEs are inert and
    pass through unchanged.
    """
    clean = refang(value)
    if ioc_type in {"domain", "ipv4", "ipv6"}:
        return clean.replace(".", "[.]")
    if ioc_type == "url":
        parsed = urlparse(clean)
        if not parsed.scheme or not parsed.netloc:
            return clean.replace("http", "hxxp").replace(".", "[.]")
        scheme = parsed.scheme.replace("http", "hxxp")
        netloc = parsed.netloc.replace(".", "[.]")
        rest = parsed.path or "/"
        if parsed.query:
            rest += f"?{parsed.query}"
        return f"{scheme}://{netloc}{rest}"
    return clean


def _fit_message(lines: list[str], *, limit: int = MAX_TELEGRAM_MESSAGE_CHARS) -> str:
    """Join lines, dropping whole trailing lines to stay under Telegram's cap.

    Truncating on line boundaries keeps the per-line HTML tags balanced; a raw
    character slice could cut an open tag and make Telegram reject the message.
    """
    message = "\n".join(lines)
    if len(message) <= limit:
        return message
    kept = list(lines)
    suffix = "…"
    while kept and len("\n".join([*kept, suffix])) > limit:
        kept.pop()
    return "\n".join([*kept, suffix])


def _why_line(attributes: dict[str, Any] | None, *, top_n: int = 3) -> str | None:
    """Top contributing evidence behind the risk score, from score_breakdown."""
    breakdown = ((attributes or {}).get("score_breakdown") or {})
    if not isinstance(breakdown, dict):
        return None
    contributions = [
        (SCORE_COMPONENT_LABELS.get(name, name), float(points))
        for name, points in breakdown.items()
        if isinstance(points, (int, float)) and float(points) >= 0.5
    ]
    if not contributions:
        return None
    contributions.sort(key=lambda pair: pair[1], reverse=True)
    parts = [f"{label} +{points:.1f}" for label, points in contributions[:top_n]]
    return " · ".join(parts)


def _normalize_ioc_display(value: str, ioc_type: str) -> str:
    display = refang(value)
    if ioc_type != "url":
        return display
    parsed = urlparse(display)
    if not parsed.scheme or not parsed.netloc:
        return display
    display = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    if parsed.query:
        display += f"?{parsed.query}"
    return display


def _normalize_link_display(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    return refang(stripped)


def _article_ioc_note(article_ioc_count: int | None) -> str | None:
    if article_ioc_count is None or article_ioc_count < ARTICLE_IOC_NOTE_THRESHOLD:
        return None
    return f"More IOCs can be found in the article/writeup ({article_ioc_count} extracted total)."


def _is_otx_reference(source: str, reference_url: str | None) -> bool:
    if str(source or "").strip().lower() == "otx":
        return True
    try:
        host = (urlparse(refang(str(reference_url or ""))).hostname or "").lower()
    except ValueError:
        return False
    return host == OTX_HOST


def _reference_link_label(source: str, reference_url: str | None) -> str:
    if _is_otx_reference(source, reference_url):
        return "OTX Pulse"
    return "Article"


def _format_source_context(source: str, attributes: dict[str, Any] | None = None) -> str:
    attrs = attributes or {}
    if source.lower() == "threatfox":
        parts: list[str] = ["ThreatFox"]
        threat_type = str(attrs.get("threat_type") or "").strip()
        malware = str(attrs.get("malware_printable") or attrs.get("malware") or "").strip()
        alias = str(attrs.get("malware") or "").strip()
        if threat_type:
            parts.append(threat_type)
        if malware:
            if alias and alias.lower() != malware.lower():
                parts.append(f"{malware} ({alias})")
            else:
                parts.append(malware)
        return " | ".join(parts)
    return source


def summarize_ioc(
    *,
    value: str,
    ioc_type: str,
    source_title: str | None = None,
    reference_url: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> str:
    lowered = f"{source_title or ''} {reference_url or ''}".lower()
    display = _normalize_ioc_display(value, ioc_type)
    attrs = attributes or {}
    threat_type = str(attrs.get("threat_type") or "").strip().lower()
    malware = str(attrs.get("malware_printable") or attrs.get("malware") or "").strip()
    if ioc_type == "ipv4":
        if threat_type == "botnet_cc":
            return f"botnet C2 IP tied to {malware}" if malware else "botnet command-and-control IP"
        if "c2" in lowered or "command and control" in lowered:
            return "IPv4 address of C2 server"
        return "IPv4 infrastructure indicator"
    if ioc_type == "ipv6":
        if "c2" in lowered or "command and control" in lowered:
            return "IPv6 address of C2 server"
        return "IPv6 infrastructure indicator"
    if ioc_type == "domain":
        if "github.io" in display:
            return "domain hosting attacker-controlled content"
        if "phish" in lowered or "lure" in lowered:
            return "domain used in phishing infrastructure"
        if "c2" in lowered or "beacon" in lowered:
            return "domain of C2 server"
        return "malicious domain indicator"
    if ioc_type == "url":
        parsed = urlparse(display)
        if parsed.hostname == "github.com" and (parsed.path or "").strip("/"):
            return "GitHub repo or path used by attacker"
        if "github.io/" in display:
            return "GitHub Pages path serving attacker content"
        if any(keyword in lowered for keyword in ("installer", "download", "payload")):
            return "malicious download or payload URL"
        if "cdn" in display.lower():
            return "malicious hosted asset or stage URL"
        return "malicious URL indicator"
    if ioc_type in {"md5", "sha1", "sha256"}:
        if "phish" in lowered or "kit" in lowered:
            return "hash of phishing kit artifact"
        if re.search(r"\b(installer|download|loader)\b", lowered):
            return "malicious installer hash"
        if any(keyword in lowered for keyword in ("beacon", "payload", "stealer", "ransomware", "malware", "sharkloader")):
            return "malware artifact hash"
        return "suspicious file hash"
    if ioc_type == "cve":
        return "referenced vulnerability identifier"
    return "suspicious indicator"


def format_alert_message(
    *,
    heading: str = "SENTINEL Alert",
    value: str,
    ioc_type: str,
    source: str,
    risk_score: float,
    severity: str,
    last_seen: datetime | str | None = None,
    source_title: str | None = None,
    reference_url: str | None = None,
    related_cves: list[str] | None = None,
    vt_detections: int | None = None,
    abuse_confidence: int | None = None,
    shodan_ports: list[int] | None = None,
    external_links: dict[str, str] | None = None,
    corroboration_sources: int | None = None,
    mitre_techniques: list[str],
    mitre_tactics: list[str],
    attributes: dict[str, Any] | None = None,
) -> str:
    attrs = attributes or {}
    emoji = SEVERITY_EMOJI.get(str(severity).lower(), "⚪")
    findings: list[str] = []
    if vt_detections is not None:
        findings.append(f"VirusTotal detections: {vt_detections}")
    if abuse_confidence is not None:
        findings.append(f"AbuseIPDB confidence: {abuse_confidence}%")
    if shodan_ports:
        findings.append(f"Shodan ports: {', '.join(str(port) for port in shodan_ports[:5])}")
    elif ioc_type in {"ipv4", "ipv6"}:
        findings.append("Shodan ports: none reported")
    findings_text = " | ".join(findings) if findings else "No external enrichment hits."
    link_anchors = [
        f'<a href="{_escape(url)}">{_escape(name)}</a>'
        for name, url in ((name, _normalize_link_display(url)) for name, url in (external_links or {}).items())
        if url
    ]
    article_href = _normalize_link_display(reference_url)
    if article_href:
        link_anchors.append(f'<a href="{_escape(article_href)}">{_escape(_reference_link_label(source, reference_url))}</a>')
    corroboration_text = f"{corroboration_sources if corroboration_sources is not None else 1} source(s)"
    summary = summarize_ioc(
        value=value,
        ioc_type=ioc_type,
        source_title=source_title,
        reference_url=reference_url,
        attributes=attributes,
    )
    source_line = _format_source_context(source, attributes)
    article_ioc_note = (
        None
        if _is_otx_reference(source, reference_url)
        else _article_ioc_note(int((attrs.get("article_ioc_count") or 0) or 0))
    )
    observed_text = _format_observed(last_seen)
    why = _why_line(attrs)
    lines = [
        f"{emoji} <b>{_escape(str(severity).upper())}</b> · Score {risk_score:.2f} · {_escape(heading)}",
    ]
    if source_title:
        lines.append(f"<b>{_escape(_truncate(str(source_title), MAX_SOURCE_TITLE_CHARS))}</b>")
    lines.append(f"<i>{_escape(source_line)}</i>")
    lines.append(f"Observed {observed_text} · Corroboration {corroboration_text}")
    if related_cves:
        lines.append(f"CVEs: {_escape(', '.join(related_cves))}")
    lines.extend(
        [
            "",
            f"<code>{_escape(_truncate(defang(value, ioc_type), MAX_IOC_VALUE_CHARS))}</code> [{_escape(ioc_type)}]",
            f"↳ {_escape(summary)}",
        ]
    )
    if article_ioc_note:
        lines.append(_escape(article_ioc_note))
    if why:
        lines.extend(["", f"<b>Why this score</b>: {_escape(why)}"])
    lines.extend(["", f"<b>Evidence</b>: {_escape(findings_text)}"])
    if link_anchors:
        lines.append("<b>Pivots</b>: " + " · ".join(link_anchors))
    if mitre_techniques or mitre_tactics:
        techniques = ", ".join(mitre_techniques) if mitre_techniques else "None"
        tactics = ", ".join(mitre_tactics) if mitre_tactics else "None"
        lines.append(f"<b>ATT&amp;CK</b>: {_escape(techniques)} · {_escape(tactics)}")
    return _fit_message(lines)


def _format_observed(last_seen: datetime | str | None) -> str:
    if last_seen is None:
        return "Unknown"
    observed: datetime | None
    if isinstance(last_seen, str):
        try:
            observed = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        except ValueError:
            observed = None
    else:
        observed = last_seen
    if observed is None:
        return "Unknown"
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    return observed.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def format_grouped_alert_message(
    *,
    heading: str = "SENTINEL Alert",
    source: str,
    risk_score: float,
    severity: str,
    iocs: list[dict[str, Any]],
    last_seen: datetime | str | None = None,
    source_title: str | None = None,
    reference_url: str | None = None,
    related_cves: list[str] | None = None,
    corroboration_sources: int | None = None,
    mitre_techniques: list[str] | None = None,
    mitre_tactics: list[str] | None = None,
    attributes: dict[str, Any] | None = None,
) -> str:
    attrs = attributes or {}
    emoji = SEVERITY_EMOJI.get(str(severity).lower(), "⚪")
    corroboration_text = f"{corroboration_sources if corroboration_sources is not None else 1} source(s)"
    observed_text = _format_observed(last_seen)

    article_ioc_count = int((attrs.get("article_ioc_count") or len(iocs)) or len(iocs))
    article_ioc_note = None if _is_otx_reference(source, reference_url) else _article_ioc_note(article_ioc_count)
    article_href = _normalize_link_display(reference_url)
    why = _why_line(attrs)
    lines = [
        f"{emoji} <b>{_escape(str(severity).upper())}</b> · Score {risk_score:.2f} · {_escape(heading)}",
        f"<b>{_escape(_truncate(str(source_title or 'Grouped writeup alert'), MAX_SOURCE_TITLE_CHARS))}</b>",
        f"<i>{_escape(source)}</i>",
        f"Observed {observed_text} · Corroboration {corroboration_text}",
    ]
    if related_cves:
        lines.append(f"CVEs: {_escape(', '.join(related_cves))}")
    if article_href:
        lines.append(f'📄 <a href="{_escape(article_href)}">{_escape(_reference_link_label(source, reference_url))}</a>')
    lines.extend(["", f"<b>IOCs ({len(iocs)})</b>"])
    if article_ioc_note:
        lines.append(_escape(article_ioc_note))
    active_label: str | None = None
    for item in iocs[:MAX_GROUPED_IOCS]:
        ioc_type = str(item.get("type", "unknown"))
        section_label = str(item.get("section_label") or "").strip() or None
        if section_label and section_label != active_label:
            lines.append(f"<u>{_escape(section_label)}</u>")
            active_label = section_label
        summary = summarize_ioc(
            value=str(item.get("value", "")),
            ioc_type=ioc_type,
            source_title=source_title,
            reference_url=reference_url,
        )
        display_value = _truncate(defang(str(item.get("value", "")), ioc_type), MAX_IOC_VALUE_CHARS)
        lines.append(f"<code>{_escape(display_value)}</code> [{_escape(ioc_type)}]")
        lines.append(f"↳ {_escape(summary)}")
    if len(iocs) > MAX_GROUPED_IOCS:
        lines.append(f"… and {len(iocs) - MAX_GROUPED_IOCS} more")
    if why:
        lines.extend(["", f"<b>Why this score</b>: {_escape(why)}"])
    if mitre_techniques or mitre_tactics:
        techniques = ", ".join(mitre_techniques or []) if mitre_techniques else "None"
        tactics = ", ".join(mitre_tactics or []) if mitre_tactics else "None"
        lines.append(f"<b>ATT&amp;CK</b>: {_escape(techniques)} · {_escape(tactics)}")
    return _fit_message(lines)


def format_daily_digest_intro(*, generated_at: str, count: int, limit: int) -> str:
    displayed = min(count, limit)
    if displayed == 0:
        return (
            "SENTINEL Daily Digest\n"
            f"Generated: {generated_at}\n"
            "No qualifying IOC activity in the last 24 hours."
        )
    return (
        "SENTINEL Daily Digest\n"
        f"Generated: {generated_at}\n"
        f"Delivering {displayed} analyst-ready IOC card(s) from the last 24 hours."
    )


def format_daily_digest_message(
    *,
    items: list[dict[str, Any]],
    generated_at: str,
    limit: int,
) -> str:
    def truncate(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    lines = [
        "SENTINEL Daily Digest",
        f"Generated: {generated_at}",
        f"Top {min(limit, len(items))} IOC(s) from the last 24 hours",
        "",
    ]
    if not items:
        lines.append("No qualifying IOC activity in the last 24 hours.")
        return "\n".join(lines)
    omitted = 0
    for index, item in enumerate(items[:limit], start=1):
        cves = ", ".join(item.get("related_cves", [])[:3]) if item.get("related_cves") else "None"
        candidate_lines = [
            f"{index}. [{item['severity'].upper()}] {item['value']} | {item['type']} | "
            f"score={float(item['risk_score']):.2f} | source={item['source']}"
        ]
        candidate_lines[0] = candidate_lines[0].replace(item["value"], truncate(str(item["value"]), MAX_IOC_VALUE_CHARS))
        if item.get("source_title"):
            candidate_lines.append(f"   Intel: {truncate(str(item['source_title']), MAX_SOURCE_TITLE_CHARS)}")
        if item.get("related_cves"):
            candidate_lines.append(f"   CVEs: {cves}")
        links = item.get("external_links") or {}
        if links:
            preferred = []
            for name in ("VirusTotal", "OTX", "URLhaus", "AbuseIPDB", "Shodan"):
                if name in links:
                    preferred.append(f"{name}: {truncate(str(links[name]), MAX_LINK_CHARS)}")
            if preferred:
                candidate_lines.append(f"   Links: {' | '.join(preferred[:MAX_DIGEST_LINKS_PER_ITEM])}")
        preview = "\n".join(lines + candidate_lines)
        if len(preview) > MAX_TELEGRAM_MESSAGE_CHARS:
            omitted = len(items[:limit]) - (index - 1)
            break
        lines.extend(candidate_lines)
    if omitted > 0:
        lines.append("")
        lines.append(f"Omitted {omitted} item(s) to keep this digest within Telegram message limits.")
    return "\n".join(lines)[:MAX_TELEGRAM_MESSAGE_CHARS]


async def build_telegram_application(token: str, callback_handler) -> Application:
    application = Application.builder().token(token).build()

    async def _handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        if query is None:
            return
        await callback_handler(query)

    application.add_handler(CallbackQueryHandler(_handle_callback))
    return application


def _detect_update_type(update: Update) -> str:
    if update.channel_post is not None:
        return "channel_post"
    if update.edited_channel_post is not None:
        return "edited_channel_post"
    if update.message is not None:
        return "message"
    if update.edited_message is not None:
        return "edited_message"
    if update.my_chat_member is not None:
        return "my_chat_member"
    if update.chat_member is not None:
        return "chat_member"
    return "unknown"


def extract_chat_candidates(updates: list[Update]) -> list[TelegramChatCandidate]:
    seen: set[str] = set()
    candidates: list[TelegramChatCandidate] = []
    for update in updates:
        chat = update.effective_chat
        if chat is None:
            continue
        chat_id = str(chat.id)
        if chat_id in seen:
            continue
        seen.add(chat_id)
        candidates.append(
            TelegramChatCandidate(
                chat_id=chat_id,
                chat_type=chat.type,
                title=getattr(chat, "title", None),
                username=getattr(chat, "username", None),
                update_type=_detect_update_type(update),
            )
        )
    return candidates


async def fetch_chat_candidates(token: str, *, limit: int = 20) -> list[TelegramChatCandidate]:
    bot = Bot(token=token)
    try:
        updates = await bot.get_updates(
            limit=limit,
            timeout=10,
            allowed_updates=[
                "message",
                "edited_message",
                "channel_post",
                "edited_channel_post",
                "my_chat_member",
                "chat_member",
            ],
        )
        return extract_chat_candidates(list(updates))
    finally:
        closer = getattr(bot, "shutdown", None)
        if closer is not None:
            maybe_awaitable = closer()
            if hasattr(maybe_awaitable, "__await__"):
                await maybe_awaitable


def format_chat_candidates(candidates: list[TelegramChatCandidate]) -> str:
    if not candidates:
        return (
            "No Telegram updates found.\n"
            "Post a fresh message in the channel or send the bot a direct message, then run this command again."
        )
    lines = ["Recent Telegram chats seen by the bot:"]
    for candidate in candidates:
        label = candidate.title or candidate.username or "Unnamed chat"
        username = f" @{candidate.username}" if candidate.username else ""
        lines.append(
            f"- chat_id={candidate.chat_id} type={candidate.chat_type} source={candidate.update_type} name={label}{username}"
        )
    return "\n".join(lines)
