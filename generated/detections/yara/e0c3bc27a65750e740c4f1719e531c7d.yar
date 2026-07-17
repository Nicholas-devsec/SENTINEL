import "hash"

rule sentinel_e0c3bc27a65750e740c4f1719e531c7d {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "e0c3bc27a65750e740c4f1719e531c7d"
}
