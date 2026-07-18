import "hash"

rule sentinel_846ef7c1c7323849b2a778c5e4cda162 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "846ef7c1c7323849b2a778c5e4cda162"
}
