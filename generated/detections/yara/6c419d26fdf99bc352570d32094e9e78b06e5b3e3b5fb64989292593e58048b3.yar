import "hash"

rule sentinel_6c419d26fdf99bc352570d32094e9e78b06e5b3e3b5fb64989292593e58048b3 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "6c419d26fdf99bc352570d32094e9e78b06e5b3e3b5fb64989292593e58048b3"
}
