from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from telegram import Bot, Chat, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, ContextTypes


MAX_TELEGRAM_MESSAGE_CHARS = 3500
MAX_DIGEST_LINKS_PER_ITEM = 2
MAX_SOURCE_TITLE_CHARS = 90
MAX_IOC_VALUE_CHARS = 120
MAX_LINK_CHARS = 140


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
                InlineKeyboardButton("Confirm Threat", callback_data=f"confirmed:{ioc_id}"),
                InlineKeyboardButton("False Positive", callback_data=f"false_positive:{ioc_id}"),
                InlineKeyboardButton("Needs Review", callback_data=f"needs_review:{ioc_id}"),
            ]
        ]
    )


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
    mitre_techniques: list[str],
    mitre_tactics: list[str],
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
    links = external_links or {}
    if links:
        intel_links = "\n".join(f"- {name}: {url}" for name, url in links.items())
    else:
        intel_links = "- None"
    cves = ", ".join(related_cves or []) if related_cves else "None"
    source_context = source_title or "None"
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
    return (
        f"{heading}\n"
        f"IOC: {value}\n"
        f"Type: {ioc_type}\n"
        f"Source: {source}\n"
        f"Observed In Feed: {observed_text}\n"
        f"Source Intel: {source_context}\n"
        f"Source Link: {reference_url or 'None'}\n"
        f"Related CVEs: {cves}\n"
        f"Score: {risk_score:.2f}\n"
        f"Severity: {severity}\n"
        f"Findings: {findings_text}\n"
        f"Intel Links:\n{intel_links}\n"
        f"ATT&CK Techniques: {techniques}\n"
        f"ATT&CK Tactics: {tactics}"
    )


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
