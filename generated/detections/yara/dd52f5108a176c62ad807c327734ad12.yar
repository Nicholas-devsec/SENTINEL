import "hash"

rule sentinel_dd52f5108a176c62ad807c327734ad12 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "dd52f5108a176c62ad807c327734ad12"
}
