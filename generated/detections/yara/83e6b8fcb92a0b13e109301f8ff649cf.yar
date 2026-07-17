import "hash"

rule sentinel_83e6b8fcb92a0b13e109301f8ff649cf {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "83e6b8fcb92a0b13e109301f8ff649cf"
}
