import "hash"

rule sentinel_6001829a128fe264b4403138700c11a8 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "6001829a128fe264b4403138700c11a8"
}
