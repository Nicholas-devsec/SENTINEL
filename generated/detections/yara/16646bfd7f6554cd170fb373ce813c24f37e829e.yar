import "hash"

rule sentinel_16646bfd7f6554cd170fb373ce813c24f37e829e {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "16646bfd7f6554cd170fb373ce813c24f37e829e"
}
