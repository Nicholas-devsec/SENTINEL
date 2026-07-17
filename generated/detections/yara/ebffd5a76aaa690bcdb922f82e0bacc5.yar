import "hash"

rule sentinel_ebffd5a76aaa690bcdb922f82e0bacc5 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "gbhackers_blog"
  condition:
    hash.md5(0, filesize) == "ebffd5a76aaa690bcdb922f82e0bacc5"
}
