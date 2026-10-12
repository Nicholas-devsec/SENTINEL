import "hash"

rule sentinel_1b4d5c95f4fc037ca3c359cea5ca2da1285bbadab12bcdcb47f3dad8bc6fa8ed {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "1b4d5c95f4fc037ca3c359cea5ca2da1285bbadab12bcdcb47f3dad8bc6fa8ed"
}
