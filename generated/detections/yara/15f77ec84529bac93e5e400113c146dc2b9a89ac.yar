import "hash"

rule sentinel_15f77ec84529bac93e5e400113c146dc2b9a89ac {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "15f77ec84529bac93e5e400113c146dc2b9a89ac"
}
