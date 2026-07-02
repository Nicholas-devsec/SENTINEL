import "hash"

rule sentinel_17c09eea41699746d301191c6a2e984d10c2f8b3 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "17c09eea41699746d301191c6a2e984d10c2f8b3"
}
