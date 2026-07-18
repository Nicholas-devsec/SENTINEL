import "hash"

rule sentinel_d6e86bf8a90e9b632add5fa495f97fbc {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "d6e86bf8a90e9b632add5fa495f97fbc"
}
