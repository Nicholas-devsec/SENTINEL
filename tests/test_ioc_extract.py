from __future__ import annotations

from sentinel.agents.ioc_extract import (
    extract_iocs_from_section,
    extract_iocs_from_text,
    find_ioc_section,
    html_to_text,
    refang,
)


def test_refang_common_conventions() -> None:
    assert refang("hxxp://evil[.]com/payload") == "http://evil.com/payload"
    assert refang("hxxps://bad[.]example[.]org") == "https://bad.example.org"
    assert refang("hxxps[:]//inventory-card-thumbzilla-ip[.]trycloudflare[.]com/De/") == "https://inventory-card-thumbzilla-ip.trycloudflare.com/De/"
    assert refang("1.2.3[.]4") == "1.2.3.4"


def test_html_to_text_strips_script_and_style() -> None:
    html = "<html><head><style>.x{}</style></head><body><script>var a=1;</script><p>C2 at 5.6.7.8</p></body></html>"
    text = html_to_text(html)
    assert "C2 at 5.6.7.8" in text
    assert "var a=1" not in text
    assert ".x{}" not in text


def test_extracts_hashes_without_substring_collisions() -> None:
    sha256 = "a" * 64
    md5 = "b" * 32
    text = f"Dropper {sha256} and loader {md5} were observed."
    extracted = {(item.type, item.value) for item in extract_iocs_from_text(text)}
    assert ("sha256", sha256) in extracted
    assert ("md5", md5) in extracted
    # No md5/sha1 phantom matches inside the sha256.
    assert not any(t == "md5" and v == "a" * 32 for t, v in extracted)
    assert not any(t == "sha1" for t, v in extracted)


def test_extracts_defanged_domain_and_url_and_ip() -> None:
    text = (
        "The campaign used hxxps://malware-delivery[.]top/stage2 with fallback C2 "
        "at 45.155.204.10 and DNS beacon to exfil[.]badcorp[.]io."
    )
    extracted = {(item.type, item.value) for item in extract_iocs_from_text(text)}
    assert ("url", "https://malware-delivery.top/stage2") in extracted
    assert ("domain", "exfil.badcorp.io") in extracted
    assert ("ipv4", "45.155.204.10") in extracted


def test_suppresses_common_benign_stun_turn_hosts() -> None:
    text = (
        "Indicators of Compromise\n"
        "http://172.86.126.18:443/update_ms.msi\n"
        "is-01-ast.ols-img-12.workers.dev\n"
        "stun2.l.google.com\n"
        "global.turn.twilio.com\n"
    )
    section = find_ioc_section(text)
    assert section is not None
    extracted = {(item.type, item.value) for item in extract_iocs_from_section(section.text)}

    assert ("url", "http://172.86.126.18:443/update_ms.msi") in extracted
    assert ("domain", "is-01-ast.ols-img-12.workers.dev") in extracted
    assert not any(value == "stun2.l.google.com" for _, value in extracted)
    assert not any(value == "global.turn.twilio.com" for _, value in extracted)


def test_suppresses_embedded_social_shortener_urls_from_articles() -> None:
    text = (
        "HollowGraph buries its C2 in M365 calendar events dated 2050. "
        "https://t.co/yJo4fpw0X9 #ThreatIntel https://x.com/threadlinqs/status/2079775946752561530 "
        "Full report: https://intel.threadlinqs.com/threat/TL-2026-1601"
    )
    extracted = {(item.type, item.value) for item in extract_iocs_from_text(text)}

    assert ("url", "https://intel.threadlinqs.com/threat/TL-2026-1601") in extracted
    assert not any(value.startswith("https://t.co/") for _, value in extracted)
    assert not any(value.startswith("https://x.com/") for _, value in extracted)


def test_defanged_email_domain_is_not_extracted_as_standalone_domain() -> None:
    text = """
Indicators of compromise (IOCs)
Indicator | Type | Role | Notes
45[.]131[.]66[.]106 | IPv4 | Command and control | Beacon destination
64[.]20[.]53[.]230 | IPv4 | Claimed exfiltration | Named in payload comment
e*******7[@]proton[.]me | Email | Extortion contact | Sole documented attacker contact channel
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy | Bitcoin address | Claimed ransom address | Sample address
CVE-2025-3248 | CVE | Initial access | Unauthenticated RCE
CVE-2021-29441 | CVE | Privilege escalation | Chained with default signing key
"""
    section = find_ioc_section(text)
    assert section is not None
    extracted = {(item.type, item.value) for item in extract_iocs_from_section(section.text)}

    assert ("ipv4", "45.131.66.106") in extracted
    assert ("ipv4", "64.20.53.230") in extracted
    assert ("cve", "CVE-2025-3248") in extracted
    assert ("cve", "CVE-2021-29441") in extracted
    assert ("domain", "proton.me") not in extracted


def test_file_artifact_name_with_defanged_dot_is_not_extracted_as_domain() -> None:
    text = """
Indicators of Compromise
Files
Delete[.]me - File observed during reconnaissance activity, commonly associated with NetScan
Network
137[.]220[.]59[.]55 - C2 infrastructure
safedata[.]s3[.]wasabisys[.]com - exfiltration destination
d6828e30ab66774a91a96ae93be4ae4c - payload hash
"""
    section = find_ioc_section(text)
    assert section is not None
    extracted = {(item.type, item.value) for item in extract_iocs_from_section(section.text)}

    assert ("domain", "delete.me") not in extracted
    assert ("domain", "safedata.s3.wasabisys.com") in extracted
    assert ("ipv4", "137.220.59.55") in extracted
    assert ("md5", "d6828e30ab66774a91a96ae93be4ae4c") in extracted


def test_script_artifact_names_with_defanged_dots_are_not_domains() -> None:
    text = """
Indicators of Compromise
Files
setup[.]mjs - obfuscated npm preinstall script
setup[.]mjs[.]malicious - Variant of setup.mjs based on TLSH pivot
Math_Symbol[.]js - first wave loader file
math_init[.]js - renamed second wave loader file
fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb
9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc
47[.]79[.]66[.]58
hxxps://npm-cache[.]com:443/router
"""
    section = find_ioc_section(text)
    assert section is not None
    extracted = {(item.type, item.value) for item in extract_iocs_from_section(section.text)}

    assert ("domain", "setup.mjs") not in extracted
    assert ("domain", "setup.mjs.malicious") not in extracted
    assert ("domain", "math_symbol.js") not in extracted
    assert ("domain", "math_init.js") not in extracted
    assert ("sha256", "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb") in extracted
    assert ("sha256", "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc") in extracted
    assert ("ipv4", "47.79.66.58") in extracted
    assert ("url", "https://npm-cache.com:443/router") in extracted


def test_extracts_gbhackers_style_ioc_table_values() -> None:
    text = (
        "URL hxxps[:]//inventory-card-thumbzilla-ip[.]trycloudflare[.]com/De/\n"
        "URL hxxps[:]//mercy-synopsis-notify-motels[.]trycloudflare[.]com/ma[.]zip\n"
        "C2 IP 62.60.190.141\n"
        "ZIP hash 55724b766ddlfe8bf9dd4cb7094b83b88d57d945\n"
    )
    extracted = {(item.type, item.value) for item in extract_iocs_from_text(text)}
    assert ("url", "https://inventory-card-thumbzilla-ip.trycloudflare.com/De/") in extracted
    assert ("url", "https://mercy-synopsis-notify-motels.trycloudflare.com/ma.zip") in extracted
    assert ("ipv4", "62.60.190.141") in extracted


def test_defanged_url_does_not_emit_duplicate_root_domain() -> None:
    text = "Download from hxxps://github[.]com/owner/repo/releases/download/payload.exe"
    extracted = {(item.type, item.value) for item in extract_iocs_from_text(text)}
    assert ("url", "https://github.com/owner/repo/releases/download/payload.exe") in extracted
    assert ("domain", "github.com") not in extracted


def test_malformed_ipv6_url_token_does_not_abort_extraction() -> None:
    text = "Ignore hxxps://[not-an-ipv6]/stage but keep C2 45.155.204.10"
    extracted = {(item.type, item.value) for item in extract_iocs_from_text(text)}

    assert ("ipv4", "45.155.204.10") in extracted
    assert not any(value == "https://[not-an-ipv6]/stage" for _, value in extracted)


def test_bare_domains_in_prose_are_not_extracted() -> None:
    text = "Researchers at example.com published findings about microsoft.com abuse."
    extracted = extract_iocs_from_text(text)
    assert not any(item.type == "domain" for item in extracted)


def test_excludes_article_own_hostname() -> None:
    text = "Read more at https://blog.vendor.com/post and the C2 https://evil.example.net/gate"
    extracted = {(item.type, item.value) for item in extract_iocs_from_text(text, exclude_hostnames={"blog.vendor.com"})}
    assert ("url", "https://evil.example.net/gate") in extracted
    assert not any("blog.vendor.com" in value for _, value in extracted)


def test_excludes_article_own_registrable_domain() -> None:
    text = (
        "Elastic published details at elastic[.]co and "
        "https://www.elastic.co/security-labs/wp2shell-wordpress-rce-detection-elastic-defend. "
        "The exploited bugs are CVE-2026-63030 and CVE-2026-60137."
    )
    extracted = {
        (item.type, item.value)
        for item in extract_iocs_from_text(text, exclude_hostnames={"www.elastic.co"})
    }

    assert ("cve", "CVE-2026-63030") in extracted
    assert ("cve", "CVE-2026-60137") in extracted
    assert ("domain", "elastic.co") not in extracted
    assert not any(item_type == "url" and "elastic.co" in value for item_type, value in extracted)


def test_extracts_cves() -> None:
    extracted = extract_iocs_from_text("Exploitation of cve-2026-12345 continues.")
    assert ("cve", "CVE-2026-12345") in {(item.type, item.value) for item in extracted}


def test_invalid_ipv4_octets_rejected() -> None:
    extracted = extract_iocs_from_text("Version 999.1.1.1 is not an address.")
    assert not any(item.type == "ipv4" for item in extracted)


ARTICLE_TEXT = """New stealer campaign
We analyzed a stealer campaign this week. Victims at contoso.com were targeted.
Indicators of Compromise
malicious-c2.badcorp.io
45.155.204.99
d41d8cd98f00b204e9800998ecf8427e
dropper.exe
Conclusion
Patch your things and read more at vendor.com."""


def test_find_ioc_section_by_heading() -> None:
    section = find_ioc_section(ARTICLE_TEXT)
    assert section is not None
    assert section.signal == "heading"
    assert "Indicators of Compromise" in section.heading
    assert "malicious-c2.badcorp.io" in section.text
    # The section ends at the next topic heading; trailing prose stays out.
    assert "vendor.com" not in section.text


def test_find_ioc_section_by_indicator_density_without_heading() -> None:
    text = "Campaign analysis follows.\n" + "\n".join(
        [
            "evil-one.badcorp.io",
            "evil-two.badcorp.io",
            "45.155.204.1",
            "45.155.204.2",
            "d41d8cd98f00b204e9800998ecf8427e",
        ]
    ) + "\nThanks for reading."
    section = find_ioc_section(text)
    assert section is not None
    assert section.signal == "indicator_density"
    assert "evil-one.badcorp.io" in section.text


def test_find_ioc_section_absent_in_plain_prose() -> None:
    text = "We discuss strategy, leadership, and the evolving threat landscape at length."
    assert find_ioc_section(text) is None


def test_ioc_heading_does_not_absorb_sources_section() -> None:
    text = """Incident Analysis
Indicators of Compromise
Sources
https://investors.coca-colacompany.com/news-events/press-releases/detail/1166/the-coca-cola-company-announces-technology-disruption-involving-fairlife-operations
https://www.cybersecuritydive.com/news/ransomware-attack-coca-cola-suspend-production-dairy/825540/
https://www.cbsnews.com/news/coca-cola-fairlife-milk-cyberattack/
"""
    assert find_ioc_section(text) is None


def test_section_extraction_takes_bare_domains_but_not_filenames() -> None:
    section = find_ioc_section(ARTICLE_TEXT)
    assert section is not None
    extracted = {(item.type, item.value) for item in extract_iocs_from_section(section.text)}
    assert ("domain", "malicious-c2.badcorp.io") in extracted
    assert ("ipv4", "45.155.204.99") in extracted
    assert ("md5", "d41d8cd98f00b204e9800998ecf8427e") in extracted
    # Dotted filenames are not domains.
    assert not any(value == "dropper.exe" for _, value in extracted)
    # Prose domains outside the section never entered it.
    assert not any(value == "contoso.com" for _, value in extracted)


def test_html_to_text_joins_table_rows_into_single_lines() -> None:
    html = (
        "<table>"
        "<tr><th>Type</th><th>Value</th></tr>"
        "<tr><td>Domain</td><td>evil[.]badcorp[.]top</td></tr>"
        "<tr><td>C2 IP</td><td>45.155.204.77</td></tr>"
        "</table>"
    )
    text = html_to_text(html)
    lines = text.splitlines()
    assert "Type | Value" in lines
    assert "Domain | evil[.]badcorp[.]top" in lines
    assert "C2 IP | 45.155.204.77" in lines


IOC_TABLE_TEXT = """Campaign analysis
The loader rotated infrastructure while delivering the stealer payload.
IOCs
Type | Value
Domain | loader-cdn[.]badcorp[.]top
C2 IP | 45.155.204.77
URL | hxxps://drop[.]badcorp[.]top/stage2.bin
SHA256 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Conclusion
Block the listed infrastructure."""


def test_type_value_table_does_not_truncate_ioc_section() -> None:
    section = find_ioc_section(IOC_TABLE_TEXT)
    assert section is not None
    # Label cells ("Domain", "C2 IP", header row) must not read as new
    # topic headings; the whole table stays inside the section.
    assert "45.155.204.77" in section.text
    assert "aaaaaaaa" in section.text
    assert "Block the listed infrastructure" not in section.text


def test_table_section_extracts_defanged_cells() -> None:
    section = find_ioc_section(IOC_TABLE_TEXT)
    assert section is not None
    extracted = {(item.type, item.value) for item in extract_iocs_from_section(section.text)}
    assert ("domain", "loader-cdn.badcorp.top") in extracted
    assert ("ipv4", "45.155.204.77") in extracted
    assert ("url", "https://drop.badcorp.top/stage2.bin") in extracted
    assert ("sha256", "a" * 64) in extracted


def test_table_section_expands_root_url_with_repo_or_path_cells() -> None:
    text = """IOCs
Type | Value | Repo | Notes
Domain | hxxps://github[.]com/ | antivirus-free-bitdefender | Fake Bitdefender GitHub download page
Domain | hxxps://bentleyvazquezpvey[.]github[.]io/ | .github/ | Arctic-Wolf
Conclusion
done"""
    section = find_ioc_section(text)
    assert section is not None
    extracted = {(item.type, item.value) for item in extract_iocs_from_section(section.text)}
    assert ("url", "https://github.com/antivirus-free-bitdefender") in extracted
    assert ("url", "https://bentleyvazquezpvey.github.io/.github/Arctic-Wolf") in extracted
    assert ("url", "https://github.com/") not in extracted


def test_table_section_expands_root_url_when_repo_suffix_is_in_same_cell() -> None:
    text = """Indicators of Compromise (IOCs)
Type | Value | Context
Domain | hxxps://github[.]com/ antivirus-free-bitdefender | Fake Bitdefender GitHub download page
Domain | hxxps://github[.]com/ malwarebytes-protection | Fake Malwarebytes GitHub download page
Domain | hxxps://github[.]com/ Arctic-Wolf-Security | Fake Arctic Wolf GitHub download page
Domain | hxxps://bentleyvazquezpvey[.]github[.]io/ .github/ Arctic-Wolf | Redirect link
"""
    section = find_ioc_section(text)
    assert section is not None
    extracted = {(item.type, item.value) for item in extract_iocs_from_section(section.text)}
    assert ("url", "https://github.com/antivirus-free-bitdefender") in extracted
    assert ("url", "https://github.com/malwarebytes-protection") in extracted
    assert ("url", "https://github.com/Arctic-Wolf-Security") in extracted
    assert ("url", "https://bentleyvazquezpvey.github.io/.github/Arctic-Wolf") in extracted
    assert ("url", "https://github.com/") not in extracted
    assert ("url", "https://bentleyvazquezpvey.github.io/") not in extracted


def test_unlabelled_indicator_table_found_by_density() -> None:
    text = "Weekly roundup of activity follows.\n" + "\n".join(
        [
            "Domain | one.badcorp.top",
            "Domain | two.badcorp.top",
            "IP | 45.155.204.1",
            "IP | 45.155.204.2",
            "MD5 | d41d8cd98f00b204e9800998ecf8427e",
        ]
    ) + "\nThat concludes the roundup."
    section = find_ioc_section(text)
    assert section is not None
    assert section.signal == "indicator_density"
    extracted = {item.value for item in extract_iocs_from_section(section.text)}
    assert {"one.badcorp.top", "two.badcorp.top", "45.155.204.1"} <= extracted


def test_mixed_bullets_and_table_layout_extracts_both() -> None:
    text = """Indicators of Compromise
- beacon[.]badcorp[.]io
- 45.155.204.5
Hashes
Type | Value
MD5 | d41d8cd98f00b204e9800998ecf8427e
Next Steps
Call your IR retainer."""
    section = find_ioc_section(text)
    assert section is not None
    extracted = {(item.type, item.value) for item in extract_iocs_from_section(section.text)}
    assert ("domain", "beacon.badcorp.io") in extracted
    assert ("ipv4", "45.155.204.5") in extracted
    # "Hashes" is a type label, not a new topic; the MD5 row stays in-section.
    assert ("md5", "d41d8cd98f00b204e9800998ecf8427e") in extracted


def test_section_extraction_respects_exclusions() -> None:
    text = "IOCs\nblog.vendor.com\nreal-c2.badcorp.io"
    section = find_ioc_section(text)
    assert section is not None
    extracted = {item.value for item in extract_iocs_from_section(section.text, exclude_hostnames={"blog.vendor.com"})}
    assert "real-c2.badcorp.io" in extracted
    assert "blog.vendor.com" not in extracted


def test_section_extraction_excludes_article_own_registrable_domain() -> None:
    text = "Indicators of Compromise\nelastic.co\nCVE-2026-63030\nCVE-2026-60137"
    section = find_ioc_section(text)
    assert section is not None
    extracted = {
        (item.type, item.value)
        for item in extract_iocs_from_section(section.text, exclude_hostnames={"www.elastic.co"})
    }

    assert ("cve", "CVE-2026-63030") in extracted
    assert ("cve", "CVE-2026-60137") in extracted
    assert ("domain", "elastic.co") not in extracted


def test_securelist_style_ioc_subheadings_are_kept_and_labeled() -> None:
    text = """Indicators of Compromise
HelloBackdoor
16C211C96735F2FAE9361B89BD7A31BF
1BFE2B9493128574907A8279256A8BCC
f9eed2f0158dc98e7012fb809152209c

HelloBackdoor Droppers:
6001829A128FE264B4403138700C11A8 - infotecs\\vipnet client\\puh.exe
EE4FF46DDD8489E81447962F927BC3F6 - infotecs\\vipnet client\\store.exe

Utility for adding exclusions to Windows Defender:
41c938b3cd7e55d4077e34976929b140

wtsapi32.dll
B103CD21280B4061F88B2BCC51394894
9F5606A0755BC633B9BD7DB6D179C09E
0CFDFFC56F0FA325D0C4D24780B46597

5.39.253.206
176.32.34.135

Detected TTPs:
T1036.004
"""
    section = find_ioc_section(text)
    assert section is not None
    extracted = extract_iocs_from_section(section.text)
    keyed = {(item.type, item.value): item.section_label for item in extracted}
    assert ("md5", "16c211c96735f2fae9361b89bd7a31bf") in keyed
    assert ("md5", "1bfe2b9493128574907a8279256a8bcc") in keyed
    assert ("md5", "f9eed2f0158dc98e7012fb809152209c") in keyed
    assert keyed[("md5", "16c211c96735f2fae9361b89bd7a31bf")] == "HelloBackdoor"
    assert keyed[("md5", "6001829a128fe264b4403138700c11a8")] == "HelloBackdoor Droppers"
    assert keyed[("md5", "41c938b3cd7e55d4077e34976929b140")] == "Utility for adding exclusions to Windows Defender"
    assert keyed[("md5", "b103cd21280b4061f88b2bcc51394894")] == "wtsapi32.dll"
    assert keyed[("ipv4", "5.39.253.206")] == "wtsapi32.dll"
    assert keyed[("ipv4", "176.32.34.135")] == "wtsapi32.dll"


def test_find_ioc_section_prefers_real_section_over_table_of_contents_entry() -> None:
    text = """Table of Contents
Persistence via the update system
Indicators of Compromise
Recommendations

Body text begins here.
Lots of prose.
Recommendations
Do the thing.
Indicators of Compromise
HelloBackdoor
16C211C96735F2FAE9361B89BD7A31BF
1BFE2B9493128574907A8279256A8BCC
5.39.253[.]206
176.32.34[.]135
Detected TTPs
T1036.004
"""
    section = find_ioc_section(text)
    assert section is not None
    assert "HelloBackdoor" in section.text
    assert "16C211C96735F2FAE9361B89BD7A31BF" in section.text
    assert "5.39.253[.]206" in section.text


def test_rapid7_style_ioc_section_ignores_toc_and_extracts_labeled_values() -> None:
    text = """Table of contents
Executive summary
MITRE ATT&CK techniques
Indicators of compromise (IOCs)
Rapid7 customers
Conclusion
Executive summary
This article references CVE-2025-33053 in prose.
MITRE ATT&CK techniques
Technique | Tactic | ID
Obtain capabilities via LLM tooling | Obtain Capabilities | AML.T0016
Indicators of compromise (IOCs)
CURP campaign
Phishing page: hxxps://gobf[.]mx
WebDav server: onedrive[.]cv
ReportFinal.<RLO>.scr SHA256
04A8018191F2E9E76072D072A933371D9D669A42DE2B2A087541CD3A653B0BA7
C2: 77.110.127.205 ports 56001-56003 / 57666 / 57777 / 57888
Domain: google.services[.]lug
Campaign tag:06x12x2026SantaEbash2 (v4.4.3)
Staging paths:
%TEMP%\\is-XXXXX.tmp\\Fo-Binary.exe
DlrtyGames campaign
Launcher: hxxps://dirty[.]example/payload
Rapid7 customers
Customers using Rapid7 gain access to all IOCs.
"""

    section = find_ioc_section(text)
    assert section is not None
    assert section.text.startswith("CURP campaign")
    extracted = {(item.type, item.value): item.section_label for item in extract_iocs_from_section(section.text)}

    assert extracted[("url", "https://gobf.mx")] == "CURP campaign"
    assert extracted[("domain", "onedrive.cv")] == "CURP campaign"
    assert extracted[("sha256", "04a8018191f2e9e76072d072a933371d9d669a42de2b2a087541cd3a653b0ba7")] == "CURP campaign"
    assert extracted[("ipv4", "77.110.127.205")] == "CURP campaign"
    assert extracted[("domain", "google.services.lug")] == "CURP campaign"
    assert extracted[("url", "https://dirty.example/payload")] == "DlrtyGames campaign"
    assert ("cve", "CVE-2025-33053") not in extracted
