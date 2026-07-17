import "hash"

rule sentinel_b4c2e16cdb513be4dc798f88e2527334 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "b4c2e16cdb513be4dc798f88e2527334"
}
