import "hash"

rule sentinel_30d9b5c56983375335bee44843115b393b7c711b {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "30d9b5c56983375335bee44843115b393b7c711b"
}
