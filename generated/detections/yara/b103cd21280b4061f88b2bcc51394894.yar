import "hash"

rule sentinel_b103cd21280b4061f88b2bcc51394894 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "b103cd21280b4061f88b2bcc51394894"
}
