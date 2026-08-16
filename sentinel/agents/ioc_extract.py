"""Extract candidate IOCs from writeup/article text.

Security writeups conventionally defang indicators (hxxp://, evil[.]com,
1.2.3[.]4). Extraction is precision-biased:

- hashes, CVEs, IPv4 addresses, and URLs are extracted whether or not defanged
- bare domains are extracted only when defanged, because prose is full of
  benign hostnames and defanging is a strong author signal that the domain is
  an indicator

The validator downstream still applies normalization, allowlisting, and
false-positive patterns to everything extracted here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlparse

import tldextract

from sentinel.agents.ioc_noise import is_article_noise_hostname


DEFANG_REPLACEMENTS = (
    ("[:]", ":"),
    ("[://]", "://"),
    ("[.]", "."),
    ("(.)", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[@]", "@"),
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("hXXps://", "https://"),
    ("hXXp://", "http://"),
)

MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\)\]]+", re.IGNORECASE)
# Only matched against text that contained defang markers (see module docstring).
# One or more `label[.]` groups followed by a letters-only TLD label.
DEFANGED_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\[\.\])+"
    r"[a-zA-Z]{2,63}\b"
)
DEFANGED_URL_SCHEME_PREFIX_RE = re.compile(r"(?:^|[^a-zA-Z0-9])h..ps?(?:\[:\]|:)\s*(?:\[//\]|//)\s*$", re.IGNORECASE)
DEFANGED_EMAIL_PREFIX_RE = re.compile(r"(?:@|\[@\])\s*$")
TLD_EXTRACT = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


@dataclass(slots=True)
class ExtractedIOC:
    type: str
    value: str
    section_label: str | None = None


def refang(text: str) -> str:
    previous = None
    while text != previous:
        previous = text
        for defanged, clean in DEFANG_REPLACEMENTS:
            text = text.replace(defanged, clean)
    return text


class _TextExtractor(HTMLParser):
    """HTML -> line-oriented text that preserves table row structure.

    Table rows are emitted as single `cell | cell | cell` lines instead of one
    line per cell. Structured IOC tables ("Type | Value", "C2 IP | 1.2.3.4")
    depend on this: with one-cell-per-line output, the type-label cells look
    like new section headings and break both section detection and indicator
    density runs.
    """

    SKIP_TAGS = {"script", "style", "noscript", "svg", "head"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0
        self._row_cells: list[str] | None = None
        self._cell_chunks: list[str] | None = None

    def _flush_cell(self) -> None:
        if self._cell_chunks is not None and self._row_cells is not None:
            cell = " ".join(self._cell_chunks).strip()
            if cell:
                self._row_cells.append(cell)
        self._cell_chunks = None

    def _flush_row(self) -> None:
        self._flush_cell()
        if self._row_cells:
            self.parts.append(" | ".join(self._row_cells))
        self._row_cells = None

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "tr":
            self._flush_row()
            self._row_cells = []
        elif tag in {"td", "th"} and self._row_cells is not None:
            self._flush_cell()
            self._cell_chunks = []

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP_TAGS:
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag in {"td", "th"}:
            self._flush_cell()
        elif tag in {"tr", "table"}:
            self._flush_row()

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = data.strip()
        if not text:
            return
        if self._cell_chunks is not None:
            self._cell_chunks.append(text)
        elif self._row_cells is not None:
            # Text directly inside <tr> outside cells; treat as its own cell.
            self._row_cells.append(text)
        else:
            self.parts.append(text)

    def close(self) -> None:
        self._flush_row()
        super().close()


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    return "\n".join(parser.parts)


def _dedupe(items: list[ExtractedIOC]) -> list[ExtractedIOC]:
    domains = {
        item.value.lower()
        for item in items
        if item.type == "domain"
    }
    url_hosts = {
        (urlparse(item.value).hostname or "").lower()
        for item in items
        if item.type == "url"
    }
    seen: set[tuple[str, str]] = set()
    result: list[ExtractedIOC] = []
    for item in items:
        key = (item.type, item.value.lower())
        if key in seen:
            continue
        if item.type == "domain" and item.value.lower() in url_hosts:
            continue
        if item.type == "domain" and any(
            other != item.value.lower() and other.endswith(f".{item.value.lower()}")
            for other in domains
        ):
            continue
        seen.add(key)
        result.append(item)
    return result


def _normalize_hostname(hostname: str | None) -> str:
    return (hostname or "").strip().lower().rstrip(".")


def _registrable_domain(hostname: str | None) -> str:
    host = _normalize_hostname(hostname)
    if not host:
        return ""
    parsed = TLD_EXTRACT(host)
    if parsed.domain and parsed.suffix:
        return f"{parsed.domain}.{parsed.suffix}".lower()
    return host


def _expand_excluded_hostnames(hostnames: set[str] | None) -> set[str]:
    excluded: set[str] = set()
    for hostname in hostnames or set():
        host = _normalize_hostname(hostname)
        if not host:
            continue
        excluded.add(host)
        excluded.add(_registrable_domain(host))
    return excluded


def _is_excluded_hostname(hostname: str | None, excluded: set[str]) -> bool:
    if not excluded:
        return False
    host = _normalize_hostname(hostname)
    if not host:
        return False
    registered = _registrable_domain(host)
    return any(
        candidate
        and (
            host == candidate
            or host.endswith(f".{candidate}")
            or registered == candidate
        )
        for candidate in excluded
    )


COMMON_BENIGN_INDICATOR_HOSTS = {
    "global.turn.twilio.com",
}
COMMON_BENIGN_INDICATOR_SUFFIXES = (
    ".turn.twilio.com",
    ".l.google.com",
)


def _is_common_benign_indicator_hostname(hostname: str | None) -> bool:
    host = _normalize_hostname(hostname)
    if not host:
        return False
    return is_article_noise_hostname(host) or host in COMMON_BENIGN_INDICATOR_HOSTS or any(
        host.endswith(suffix)
        for suffix in COMMON_BENIGN_INDICATOR_SUFFIXES
    )


def _looks_like_path_fragment(text: str) -> bool:
    stripped = refang(text.strip())
    if not stripped or len(stripped) > 80 or " " in stripped:
        return False
    if _is_indicator_type_label(stripped):
        return False
    token = stripped.rstrip(",;")
    if URL_RE.fullmatch(token) or IPV4_RE.fullmatch(token) or CVE_RE.fullmatch(token):
        return False
    if MD5_RE.fullmatch(token) or SHA1_RE.fullmatch(token) or SHA256_RE.fullmatch(token):
        return False
    if BARE_DOMAIN_RE.fullmatch(token.rstrip(".")) and token.rsplit(".", 1)[-1].lower() not in FILE_EXTENSIONS:
        return False
    return re.fullmatch(r"[A-Za-z0-9._/\-]+", token) is not None


def _augment_root_urls_with_path_cells(section_text: str, found: list[ExtractedIOC]) -> list[ExtractedIOC]:
    replacements: dict[str, list[str]] = {}
    for line in section_text.splitlines():
        cells = [refang(cell.strip()) for cell in line.split("|") if cell.strip()]
        if len(cells) < 2:
            continue
        for index, cell in enumerate(cells):
            parts = cell.split()
            if not parts:
                continue
            candidate = parts[0].rstrip(".,;")
            if not URL_RE.fullmatch(candidate):
                continue
            parsed = urlparse(candidate)
            if parsed.scheme not in {"http", "https"} or (parsed.path or "/") != "/" or not parsed.netloc:
                continue
            root_url = candidate
            path_parts: list[str] = []
            for part in parts[1:]:
                if not _looks_like_path_fragment(part):
                    break
                path_parts.append(part.strip("/"))
            if not path_parts:
                for extra_cell in cells[index + 1 :]:
                    if not _looks_like_path_fragment(extra_cell):
                        break
                    path_parts.append(extra_cell.strip("/"))
            if not path_parts:
                continue
            specific_url = root_url.rstrip("/") + "/" + "/".join(part for part in path_parts if part)
            if specific_url != root_url:
                replacements.setdefault(root_url.lower(), [])
                if specific_url not in replacements[root_url.lower()]:
                    replacements[root_url.lower()].append(specific_url)

    if not replacements:
        return found

    augmented: list[ExtractedIOC] = []
    for item in found:
        if item.type == "url":
            replacement_urls = replacements.get(item.value.lower())
            if replacement_urls is not None:
                for replacement in replacement_urls:
                    augmented.append(ExtractedIOC(type="url", value=replacement))
                continue
        augmented.append(item)
    return _dedupe(augmented)


def _is_domain_embedded_in_defanged_url(text: str, span: tuple[int, int]) -> bool:
    start, end = span
    prefix = text[max(0, start - 24) : start]
    suffix = text[end : min(len(text), end + 3)]
    if DEFANGED_URL_SCHEME_PREFIX_RE.search(prefix) is None:
        return False
    return not suffix or suffix.startswith(("/", "[", "?", "#", ":", ".", ",", ";"))


def _is_domain_embedded_in_defanged_email(text: str, span: tuple[int, int]) -> bool:
    start, end = span
    prefix = text[max(0, start - 12) : start]
    suffix = text[end : min(len(text), end + 8)]
    if DEFANGED_EMAIL_PREFIX_RE.search(prefix) is None:
        return False
    return not suffix or suffix.startswith((" ", "\t", "\n", "\r", ",", ";", ")", "]", "|"))


FILE_ARTIFACT_CONTEXT_TERMS = (
    "file observed",
    "file name",
    "filename",
    "file path",
    "process",
    "executable",
    "binary",
    "artifact",
)
NETWORK_CONTEXT_TERMS = (
    "beacon",
    "c2",
    "command and control",
    "destination",
    "dns",
    "domain",
    "exfiltration",
    "host",
    "hostname",
    "infrastructure",
    "ip",
    "server",
    "url",
)
FILE_ARTIFACT_DESCRIPTOR_LABELS = {
    "artifact",
    "backdoor",
    "dropper",
    "infected",
    "loader",
    "malicious",
    "payload",
    "sample",
    "variant",
}


def _is_domain_in_file_artifact_context(section_text: str, value: str) -> bool:
    target = value.strip().lower()
    if not target:
        return False
    for line in section_text.splitlines():
        clean = refang(line).lower()
        if target not in clean:
            continue
        if any(term in clean for term in NETWORK_CONTEXT_TERMS):
            return False
        if any(term in clean for term in FILE_ARTIFACT_CONTEXT_TERMS):
            return True
    return False


def _looks_like_file_artifact_domain(value: str) -> bool:
    labels = [label for label in value.strip().lower().split(".") if label]
    if not labels:
        return False
    suffix = labels[-1]
    if suffix in FILE_EXTENSIONS:
        return True
    return suffix in FILE_ARTIFACT_DESCRIPTOR_LABELS and any(
        label in FILE_EXTENSIONS for label in labels[1:-1]
    )


def extract_iocs_from_text(text: str, *, exclude_hostnames: set[str] | None = None) -> list[ExtractedIOC]:
    """Extract candidate IOCs from prose. exclude_hostnames drops the article's own infrastructure."""
    excluded = _expand_excluded_hostnames(exclude_hostnames)
    found: list[ExtractedIOC] = []

    # Defanged domains are matched on the raw text before refanging so the
    # defang marker itself acts as the confidence signal.
    for match in DEFANGED_DOMAIN_RE.finditer(text):
        if _is_domain_embedded_in_defanged_url(text, match.span()):
            continue
        if _is_domain_embedded_in_defanged_email(text, match.span()):
            continue
        domain = match.group(0).replace("[.]", ".").rstrip(".").lower()
        if _looks_like_file_artifact_domain(domain):
            continue
        if not _is_excluded_hostname(domain, excluded) and not _is_common_benign_indicator_hostname(domain):
            found.append(ExtractedIOC(type="domain", value=domain))

    clean = refang(text)

    # SHA256 first so shorter hash regexes don't match substrings of longer ones.
    sha256_spans: list[tuple[int, int]] = []
    for match in SHA256_RE.finditer(clean):
        sha256_spans.append(match.span())
        found.append(ExtractedIOC(type="sha256", value=match.group(0).lower()))

    def inside_longer(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
        return any(start <= span[0] and span[1] <= end for start, end in spans)

    sha1_spans: list[tuple[int, int]] = []
    for match in SHA1_RE.finditer(clean):
        if inside_longer(match.span(), sha256_spans):
            continue
        sha1_spans.append(match.span())
        found.append(ExtractedIOC(type="sha1", value=match.group(0).lower()))

    for match in MD5_RE.finditer(clean):
        if inside_longer(match.span(), sha256_spans) or inside_longer(match.span(), sha1_spans):
            continue
        found.append(ExtractedIOC(type="md5", value=match.group(0).lower()))

    for match in CVE_RE.finditer(clean):
        found.append(ExtractedIOC(type="cve", value=match.group(0).upper()))

    for match in URL_RE.finditer(clean):
        url = match.group(0).rstrip(".,;")
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if host and not _is_excluded_hostname(host, excluded) and not _is_common_benign_indicator_hostname(host):
            found.append(ExtractedIOC(type="url", value=url))

    for match in IPV4_RE.finditer(clean):
        octets = match.group(0).split(".")
        if all(0 <= int(octet) <= 255 for octet in octets):
            found.append(ExtractedIOC(type="ipv4", value=match.group(0)))

    return _dedupe(found)


# --- IOC section detection ---------------------------------------------------
#
# Vendor writeups that are worth an analyst's time usually end with an explicit
# indicator section ("Indicators of Compromise", "IOCs", an indicators table).
# Detecting that section lets discovery extract from the author's own curated
# list (high fidelity) and skip pages that never commit to concrete indicators.

DEFAULT_SECTION_SIGNALS = (
    "indicators of compromise",
    "indicator of compromise",
    "iocs",
    "ioc",
    "indicators",
    "atomic indicators",
    "network indicators",
    "file indicators",
    "file hashes",
    "c2 infrastructure",
    "c2 servers",
)

# A "heading" is a short standalone line; prose sentences don't qualify.
MAX_HEADING_CHARS = 80
# Structural fallback: this many consecutive indicator-shaped lines counts as
# an indicator table even without a labelled heading.
MIN_DENSITY_RUN = 5
MIN_DENSITY_STRONG_LINES = 2

BARE_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
# Trailing labels that make a dotted token a filename, not a domain.
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "mjs", "cjs",
    "jsx", "ts", "tsx", "jar", "py", "sh", "svg", "svgz",
    "zip", "rar", "7z", "gz", "tar", "iso", "img", "bin", "dat", "tmp", "log",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "txt", "csv",
    "lnk", "scr", "msi", "hta", "chm", "php", "asp", "aspx", "jsp", "html", "htm",
    "json", "map", "lock", "yaml", "yml", "toml",
}


@dataclass(slots=True)
class IOCSection:
    heading: str
    text: str
    signal: str  # "heading" | "indicator_density"


def _is_heading_line(line: str, signals: tuple[str, ...] | list[str]) -> bool:
    stripped = line.strip()
    if not stripped or len(stripped) > MAX_HEADING_CHARS:
        return False
    lowered = stripped.lower().rstrip(":")
    return any(signal in lowered for signal in signals)


def _next_nonempty_line(lines: list[str], start_index: int) -> str | None:
    for candidate in lines[start_index:]:
        stripped = candidate.strip()
        if stripped:
            return stripped
    return None


def _is_table_of_contents_heading(lines: list[str], index: int) -> bool:
    """Ignore headings repeated in a table of contents before article body."""
    near_toc = False
    seen_nonempty = 0
    for candidate in reversed(lines[max(0, index - 20) : index]):
        stripped = candidate.strip().lower()
        if not stripped:
            continue
        seen_nonempty += 1
        if stripped == "table of contents":
            near_toc = True
            break
        if seen_nonempty >= 12:
            return False
    if not near_toc:
        return False
    following_topics = 0
    for candidate in lines[index + 1 : index + 8]:
        stripped = candidate.strip()
        if not stripped:
            continue
        if _looks_like_indicator_line(stripped):
            return False
        if len(stripped) <= 80 and len(stripped.split()) <= 8:
            following_topics += 1
            if following_topics >= 2:
                return True
            continue
        return False
    return False


# Labels that commonly appear beside indicator values in IOC tables and lists.
# A line/cell that is only one of these must never terminate an IOC section.
INDICATOR_TYPE_LABELS = {
    "type", "value", "indicator", "indicators", "description", "notes",
    "domain", "domains", "url", "urls", "ip", "ips", "ip address", "ip addresses",
    "ipv4", "ipv6", "c2", "c2 ip", "c2 server", "c2 servers", "c2 domain",
    "hash", "hashes", "file hash", "file hashes", "md5", "sha1", "sha256",
    "sha-1", "sha-256", "filename", "filenames", "file name", "file names",
    "email", "emails", "cve",
}
NON_IOC_SECTION_HEADINGS = {
    "acknowledgements",
    "additional reading",
    "citations",
    "conclusion",
    "external links",
    "further reading",
    "references",
    "related articles",
    "related links",
    "source",
    "sources",
}


def _is_indicator_type_label(text: str) -> bool:
    return text.strip().rstrip(":").strip().lower() in INDICATOR_TYPE_LABELS


def _is_non_ioc_section_heading(text: str) -> bool:
    normalized = text.strip().rstrip(":").strip().lower()
    return normalized in NON_IOC_SECTION_HEADINGS


JAVA_IDENTIFIER_CONTEXT_TERMS = (
    "cause-exception",
    "cause-message",
    "class",
    "converter-type",
    "debugging information",
    "exception",
    "import ",
    "java.",
    "nested exception",
    "package ",
    "required-type",
    "root cause",
    "stack trace",
    "threw exception",
)
JAVA_PACKAGE_ROOTS = {
    "com",
    "freemarker",
    "java",
    "javax",
    "jakarta",
    "jetbrains",
    "net",
    "org",
    "sun",
}


def _looks_like_java_identifier_domain(token: str, *, context: str) -> bool:
    cleaned = refang(token).strip().rstrip(",;:.").strip()
    labels = [label for label in cleaned.split(".") if label]
    lowered = [label.lower() for label in labels]
    if len(lowered) < 3:
        return False
    if not lowered or lowered[0] not in JAVA_PACKAGE_ROOTS:
        return False
    if any(label in FILE_EXTENSIONS for label in lowered):
        return False
    context_lower = refang(context).lower()
    has_java_context = any(term in context_lower for term in JAVA_IDENTIFIER_CONTEXT_TERMS)
    has_class_case = any(any(char.isupper() for char in label) for label in labels)
    return has_java_context or has_class_case or len(lowered) >= 4


def _cell_indicator_token(cell: str) -> str | None:
    """Indicator-shaped token from a short list/table cell, if one exists."""
    stripped = refang(cell.strip().lstrip("-*•").strip())
    if not stripped:
        return None
    parts = stripped.split()
    for part in parts:
        token = part.strip().rstrip(",;")
        if MD5_RE.fullmatch(token) or SHA1_RE.fullmatch(token) or SHA256_RE.fullmatch(token):
            return token
        if URL_RE.fullmatch(token) or CVE_RE.fullmatch(token):
            return token
        if IPV4_RE.fullmatch(token):
            return token
        if (
            len(parts) <= 5
            and BARE_DOMAIN_RE.fullmatch(token)
            and token.rsplit(".", 1)[-1].lower() not in FILE_EXTENSIONS
            and not _looks_like_java_identifier_domain(token, context=cell)
        ):
            return token
    token = parts[0].rstrip(",;")
    if (
        len(parts) <= 5
        and BARE_DOMAIN_RE.fullmatch(token)
        and token.rsplit(".", 1)[-1].lower() not in FILE_EXTENSIONS
        and not _looks_like_java_identifier_domain(token, context=cell)
    ):
        return token
    return None


def _is_strong_indicator_token(token: str) -> bool:
    return (
        MD5_RE.fullmatch(token) is not None
        or SHA1_RE.fullmatch(token) is not None
        or SHA256_RE.fullmatch(token) is not None
        or URL_RE.fullmatch(token) is not None
        or CVE_RE.fullmatch(token) is not None
        or IPV4_RE.fullmatch(token) is not None
    )


def _looks_like_indicator_line(line: str) -> bool:
    cells = [cell for cell in line.split("|") if cell.strip()]
    if not cells or len(cells) > 4:
        return False
    return any(_cell_indicator_token(cell) is not None for cell in cells)


def _looks_like_section_subheading(line: str, next_nonempty: str | None) -> bool:
    stripped = line.strip()
    if not stripped or _looks_like_indicator_line(line) or _is_indicator_type_label(stripped):
        return False
    normalized_tokens = {
        token.strip().rstrip(":").lower()
        for token in re.split(r"\s+", stripped)
        if token.strip()
    }
    if normalized_tokens & {"md5", "sha1", "sha-1", "sha256", "sha-256", "hash", "hashes"}:
        return False
    if len(stripped) > MAX_HEADING_CHARS:
        return False
    if next_nonempty is None or not _looks_like_indicator_line(next_nonempty):
        return False
    return len(stripped.split()) <= 8


def _contains_hash_descriptor(line: str) -> bool:
    normalized_tokens = {
        token.strip().rstrip(":").lower()
        for token in re.split(r"\s+", line.strip())
        if token.strip()
    }
    return bool(normalized_tokens & {"md5", "sha1", "sha-1", "sha256", "sha-256", "hash", "hashes"})


def _strong_indicator_line_count(lines: list[str]) -> int:
    strong = 0
    for line in lines:
        cells = [cell for cell in line.split("|") if cell.strip()]
        if any(
            token is not None and _is_strong_indicator_token(token)
            for token in (_cell_indicator_token(cell) for cell in cells)
        ):
            strong += 1
    return strong


def find_ioc_section(
    text: str, *, signals: tuple[str, ...] | list[str] = DEFAULT_SECTION_SIGNALS
) -> IOCSection | None:
    """Locate an explicit IOC/indicators section, or an unlabelled indicator table."""
    lines = text.splitlines()

    def is_next_topic_heading(line: str, collected_indicators: int, next_nonempty: str | None) -> bool:
        """A short capitalized non-indicator line after indicators = new section."""
        stripped = line.strip()
        if not stripped or collected_indicators == 0:
            return False
        # Table/list layouts interleave label cells ("Domain", "SHA256",
        # "Type | Value") with indicator values; labels continue the section.
        if all(_is_indicator_type_label(cell) for cell in stripped.split("|") if cell.strip()):
            return False
        if ":" in stripped:
            return False
        if _contains_hash_descriptor(stripped):
            return False
        if _looks_like_section_subheading(line, next_nonempty):
            return False
        return (
            len(stripped) <= 60
            and len(stripped.split()) <= 6
            and stripped[0].isupper()
            and not _looks_like_indicator_line(line)
            and not any(signal in stripped.lower() for signal in signals)
        )

    best_heading_section: IOCSection | None = None
    best_heading_score: tuple[int, int, int] | None = None
    for index, line in enumerate(lines):
        if not _is_heading_line(line, signals):
            continue
        if _is_table_of_contents_heading(lines, index):
            continue
        body: list[str] = []
        indicator_count = 0
        for offset, candidate in enumerate(lines[index + 1 :], start=index + 2):
            next_nonempty = _next_nonempty_line(lines, offset)
            if _is_non_ioc_section_heading(candidate):
                break
            if is_next_topic_heading(candidate, indicator_count, next_nonempty):
                break
            body.append(candidate)
            if _looks_like_indicator_line(candidate):
                indicator_count += 1
            if len(body) >= 400:
                break
        section_text = "\n".join(body).strip()
        if section_text:
            strong_count = _strong_indicator_line_count(body)
            score = (indicator_count, strong_count, index)
            if best_heading_score is None or score > best_heading_score:
                best_heading_score = score
                best_heading_section = IOCSection(heading=line.strip(), text=section_text, signal="heading")

    if best_heading_section is not None:
        return best_heading_section

    # Structural fallback: a dense run of indicator-shaped lines.
    run: list[str] = []
    for line in [*lines, ""]:
        if _looks_like_indicator_line(line):
            run.append(line)
            continue
        if len(run) >= MIN_DENSITY_RUN and _strong_indicator_line_count(run) >= MIN_DENSITY_STRONG_LINES:
            return IOCSection(heading="", text="\n".join(run), signal="indicator_density")
        run = []
    return None


def extract_iocs_from_section(
    section_text: str, *, exclude_hostnames: set[str] | None = None
) -> list[ExtractedIOC]:
    """Extraction inside a detected IOC section.

    Indicator lists are frequently NOT defanged, so in addition to the normal
    precision rules this extracts bare domains — but only from lines that look
    like list entries, and never dotted filenames.
    """
    excluded = _expand_excluded_hostnames(exclude_hostnames)
    found = extract_iocs_from_text(section_text, exclude_hostnames=excluded)
    found = _augment_root_urls_with_path_cells(section_text, found)

    label_by_key: dict[tuple[str, str], str | None] = {}
    found_keys = {(item.type, item.value.lower()) for item in found}
    url_hosts = {
        (urlparse(item.value).hostname or "").lower() for item in found if item.type == "url"
    }
    lines = section_text.splitlines()
    current_label: str | None = None
    for index, line in enumerate(lines):
        next_nonempty = _next_nonempty_line(lines, index + 1)
        if _looks_like_section_subheading(line, next_nonempty):
            current_label = line.strip().rstrip(":").strip()
            continue
        for item in extract_iocs_from_text(line, exclude_hostnames=excluded):
            key = (item.type, item.value.lower())
            if key not in found_keys:
                found.append(item)
                found_keys.add(key)
            label_by_key.setdefault(key, current_label)
        # Table rows arrive as `label | value` lines; treat each cell as a
        # potential bare-domain list entry.
        for cell in line.split("|"):
            stripped = refang(cell.strip().lstrip("-*•").strip())
            if not stripped or len(stripped.split()) > 5:
                continue
            for part in stripped.split():
                token = part.rstrip(",;").rstrip(".").lower()
                if not BARE_DOMAIN_RE.fullmatch(token):
                    continue
                if token.rsplit(".", 1)[-1] in FILE_EXTENSIONS:
                    continue
                if _looks_like_java_identifier_domain(part, context=line):
                    continue
                if (
                    _is_excluded_hostname(token, excluded)
                    or _is_common_benign_indicator_hostname(token)
                    or token in url_hosts
                ):
                    continue
                key = ("domain", token)
                if key not in found_keys:
                    found.append(ExtractedIOC(type="domain", value=token))
                    found_keys.add(key)
                label_by_key.setdefault(("domain", token), current_label)

    found = _augment_root_urls_with_path_cells(section_text, found)
    found = _dedupe(found)
    found = [
        item
        for item in found
        if item.type != "domain" or not _is_domain_in_file_artifact_context(section_text, item.value)
    ]

    enriched: list[ExtractedIOC] = []
    seen: set[tuple[str, str]] = set()
    for item in found:
        key = (item.type, item.value.lower())
        if key in seen:
            continue
        seen.add(key)
        enriched.append(
            ExtractedIOC(
                type=item.type,
                value=item.value,
                section_label=label_by_key.get(key),
            )
        )
    return enriched
