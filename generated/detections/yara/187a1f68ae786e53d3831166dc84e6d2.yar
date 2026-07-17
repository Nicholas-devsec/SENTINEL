import "hash"

rule sentinel_187a1f68ae786e53d3831166dc84e6d2 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "187a1f68ae786e53d3831166dc84e6d2"
}
