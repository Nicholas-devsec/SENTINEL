import "hash"

rule sentinel_f9eed2f0158dc98e7012fb809152209c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "f9eed2f0158dc98e7012fb809152209c"
}
