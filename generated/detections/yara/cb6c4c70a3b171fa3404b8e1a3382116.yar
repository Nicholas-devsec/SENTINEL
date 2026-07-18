import "hash"

rule sentinel_cb6c4c70a3b171fa3404b8e1a3382116 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "cb6c4c70a3b171fa3404b8e1a3382116"
}
