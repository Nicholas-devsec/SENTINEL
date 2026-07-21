import "hash"

rule sentinel_f46c01a5be2e08e36d4ec3302a8650a6ed25ec14 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha1(0, filesize) == "f46c01a5be2e08e36d4ec3302a8650a6ed25ec14"
}
