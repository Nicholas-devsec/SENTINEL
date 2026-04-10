---
version: 1.0.0
last_updated: 2026-04-08
updated_by: human
---

# Validation Skill

## IOC Patterns
- Validate IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, and CVE formats.
- Reject malformed indicators before persistence.

## False Positive Rules
- Reject RFC1918, localhost, loopback, and documentation-only test values.
- Reject entries present in the Tranco top domains allowlist.

## Deduplication
- Normalize values consistently before hashing and comparison.
- Deduplicate on the SHA-256 of the normalized IOC value.

## Learner Updates
<!-- learner: append here -->

