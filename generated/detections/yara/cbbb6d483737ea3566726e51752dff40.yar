import "hash"

rule sentinel_cbbb6d483737ea3566726e51752dff40 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "cbbb6d483737ea3566726e51752dff40"
}
