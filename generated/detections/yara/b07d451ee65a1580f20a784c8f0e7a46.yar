import "hash"

rule sentinel_b07d451ee65a1580f20a784c8f0e7a46 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "b07d451ee65a1580f20a784c8f0e7a46"
}
