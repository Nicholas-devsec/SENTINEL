import "hash"

rule sentinel_7f223ee0716ce2ad56f55d3744419449 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "7f223ee0716ce2ad56f55d3744419449"
}
