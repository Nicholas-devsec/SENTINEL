import "hash"

rule sentinel_16c211c96735f2fae9361b89bd7a31bf {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "16c211c96735f2fae9361b89bd7a31bf"
}
