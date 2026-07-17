import "hash"

rule sentinel_31323334353637383930616263646566 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "31323334353637383930616263646566"
}
