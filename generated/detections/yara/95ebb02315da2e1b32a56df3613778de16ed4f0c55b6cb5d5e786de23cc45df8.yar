import "hash"

rule sentinel_95ebb02315da2e1b32a56df3613778de16ed4f0c55b6cb5d5e786de23cc45df8 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "95ebb02315da2e1b32a56df3613778de16ed4f0c55b6cb5d5e786de23cc45df8"
}
