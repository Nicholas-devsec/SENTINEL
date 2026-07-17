import "hash"

rule sentinel_acd31c9941b6c1cabd4e45e6877b9038 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "acd31c9941b6c1cabd4e45e6877b9038"
}
