import "hash"

rule sentinel_d08a059e8b815e3b891505bc8777fc28 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "gbhackers_blog"
  condition:
    hash.md5(0, filesize) == "d08a059e8b815e3b891505bc8777fc28"
}
