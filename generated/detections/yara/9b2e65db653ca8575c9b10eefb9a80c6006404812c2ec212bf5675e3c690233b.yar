import "hash"

rule sentinel_9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha256(0, filesize) == "9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b"
}
