import "hash"

rule sentinel_11dbc8a2bea04b15f8f68f3f01e8faf9 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "11dbc8a2bea04b15f8f68f3f01e8faf9"
}
