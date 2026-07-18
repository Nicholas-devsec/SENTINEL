from __future__ import annotations

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
MAX_GROUPED_IOCS = 12
ARTICLE_IOC_NOTE_THRESHOLD = 10


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
                InlineKeyboardButton("TP", callback_data=f"confirmed:{ioc_id}"),
                InlineKeyboardButton("FP", callback_data=f"false_positive:{ioc_id}"),
            ],
        ]
    )


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


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
    if article_ioc_count is None or article_ioc_count <= ARTICLE_IOC_NOTE_THRESHOLD:
        return None
    return f"More IOCs are present in the article ({article_ioc_count} extracted total)."


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
    techniques = ", ".join(mitre_techniques) if mitre_techniques else "None"
    tactics = ", ".join(mitre_tactics) if mitre_tactics else "None"
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
    attrs = attributes or {}
    links = {name: _normalize_link_display(url) or "" for name, url in (external_links or {}).items()}
    links = {name: url for name, url in links.items() if url}
    if links:
        intel_links = "\n".join(f"- {name}: {url}" for name, url in links.items())
    else:
        intel_links = "- None"
    cves = ", ".join(related_cves or []) if related_cves else "None"
    source_context = source_title or "None"
    corroboration_text = (
        f"{corroboration_sources} source(s)" if corroboration_sources is not None else "1 source(s)"
    )
    summary = summarize_ioc(
        value=value,
        ioc_type=ioc_type,
        source_title=source_title,
        reference_url=reference_url,
        attributes=attributes,
    )
    source_line = _format_source_context(source, attributes)
    article_ioc_note = _article_ioc_note(int((attrs.get("article_ioc_count") or 0) or 0))
    observed_text = "Unknown"
    if last_seen is not None:
        if isinstance(last_seen, str):
            try:
                observed = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            except ValueError:
                observed = None
        else:
            observed = last_seen
        if observed is not None:
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=UTC)
            observed_text = observed.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        heading,
        f"{source_context}",
        f"{severity.upper()} | Score {risk_score:.2f} | 1 IOC",
        f"Source {source_line}",
        f"Observed {observed_text} | Corroboration {corroboration_text}",
        f"CVEs {cves}",
        f"Article {_normalize_link_display(reference_url) or 'None'}",
        "",
        "IOC",
        f"- [{ioc_type}] {_truncate(_normalize_ioc_display(value, ioc_type), 140)}",
        f"  {summary}",
        "",
        "Context",
    ]
    if article_ioc_note:
        lines.append(article_ioc_note)
    lines.extend(
        [
            f"Findings {findings_text}",
            "Intel Links",
            intel_links,
            f"ATT&CK {techniques}",
            f"Tactics {tactics}",
        ]
    )
    return "\n".join(lines)[:MAX_TELEGRAM_MESSAGE_CHARS]


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
    techniques = ", ".join(mitre_techniques or []) if mitre_techniques else "None"
    tactics = ", ".join(mitre_tactics or []) if mitre_tactics else "None"
    cves = ", ".join(related_cves or []) if related_cves else "None"
    corroboration_text = (
        f"{corroboration_sources} source(s)" if corroboration_sources is not None else "1 source(s)"
    )
    observed_text = "Unknown"
    if last_seen is not None:
        if isinstance(last_seen, str):
            try:
                observed = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            except ValueError:
                observed = None
        else:
            observed = last_seen
        if observed is not None:
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=UTC)
            observed_text = observed.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")

    article_ioc_count = int((attrs.get("article_ioc_count") or len(iocs)) or len(iocs))
    article_ioc_note = _article_ioc_note(article_ioc_count)
    article_line = f"Article {_normalize_link_display(reference_url)}" if reference_url else "Article None"
    lines = [
        heading,
        f"{source_title or 'Grouped writeup alert'}",
        f"{severity.upper()} | Score {risk_score:.2f} | {len(iocs)} IOC(s)",
        f"Source {source}",
        f"Observed {observed_text} | Corroboration {corroboration_text}",
        f"CVEs {cves}",
        article_line,
        "",
        "IOCs",
    ]
    if article_ioc_note:
        lines.append(article_ioc_note)
    active_label: str | None = None
    for item in iocs[:MAX_GROUPED_IOCS]:
        ioc_type = str(item.get("type", "unknown"))
        value = _normalize_ioc_display(str(item.get("value", "")), ioc_type)
        section_label = str(item.get("section_label") or "").strip() or None
        if section_label and section_label != active_label:
            lines.append(section_label)
            active_label = section_label
        summary = summarize_ioc(
            value=str(item.get("value", "")),
            ioc_type=ioc_type,
            source_title=source_title,
            reference_url=reference_url,
        )
        lines.append(f"- [{ioc_type}] {_truncate(value, 140)}")
        lines.append(f"  {summary}")
    if len(iocs) > MAX_GROUPED_IOCS:
        lines.append(f"- ... and {len(iocs) - MAX_GROUPED_IOCS} more")
    lines.extend(
        [
            "",
            "Context",
            "Grouped by shared article/source link to avoid duplicate alert spam.",
            f"ATT&CK {techniques}",
            f"Tactics {tactics}",
        ]
    )
    return "\n".join(lines)[:MAX_TELEGRAM_MESSAGE_CHARS]


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
