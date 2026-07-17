import "hash"

rule sentinel_a7e18d96efd3cdb127ef4cdcad9e3ad26c482bf2 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha1(0, filesize) == "a7e18d96efd3cdb127ef4cdcad9e3ad26c482bf2"
}
