import "hash"

rule sentinel_1bfe2b9493128574907a8279256a8bcc {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "1bfe2b9493128574907a8279256a8bcc"
}
