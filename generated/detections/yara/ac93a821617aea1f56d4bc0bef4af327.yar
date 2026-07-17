import "hash"

rule sentinel_ac93a821617aea1f56d4bc0bef4af327 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "ac93a821617aea1f56d4bc0bef4af327"
}
