import "hash"

rule sentinel_9f5606a0755bc633b9bd7db6d179c09e {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "9f5606a0755bc633b9bd7db6d179c09e"
}
