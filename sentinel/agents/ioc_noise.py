from __future__ import annotations

from urllib.parse import urlparse


# URLs from embedded posts/share widgets are common in vendor blogs and are not
# indicators by themselves. Apply this only to article/discovery extraction and
# validation, not to direct threat-feed URL IOCs.
ARTICLE_NOISE_HOSTS = {
    "bit.ly",
    "bitly.com",
    "buff.ly",
    "cutt.ly",
    "fb.me",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "t.ly",
    "tinyurl.com",
    "x.com",
}
ARTICLE_NOISE_SUFFIXES = (
    ".facebook.com",
    ".linkedin.com",
    ".twitter.com",
    ".x.com",
)


def is_article_noise_hostname(hostname: str | None) -> bool:
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    return host in ARTICLE_NOISE_HOSTS or any(host.endswith(suffix) for suffix in ARTICLE_NOISE_SUFFIXES)


def is_article_noise_url(value: str | None) -> bool:
    if not value:
        return False
    try:
        host = urlparse(value.strip()).hostname
    except ValueError:
        return False
    return is_article_noise_hostname(host)
