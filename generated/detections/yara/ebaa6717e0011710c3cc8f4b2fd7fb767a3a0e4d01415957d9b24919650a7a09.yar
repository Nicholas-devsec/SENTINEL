import "hash"

rule sentinel_ebaa6717e0011710c3cc8f4b2fd7fb767a3a0e4d01415957d9b24919650a7a09 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "ebaa6717e0011710c3cc8f4b2fd7fb767a3a0e4d01415957d9b24919650a7a09"
}
