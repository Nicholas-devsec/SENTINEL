import "hash"

rule sentinel_7efb9e34f0829837d0b8b8ec33124b2e68c2ee15f1c222afc7c2d4ed985f96d5 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "7efb9e34f0829837d0b8b8ec33124b2e68c2ee15f1c222afc7c2d4ed985f96d5"
}
