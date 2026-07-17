import "hash"

rule sentinel_7306885bb4c98f2a9f056104cf092bc9 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "7306885bb4c98f2a9f056104cf092bc9"
}
