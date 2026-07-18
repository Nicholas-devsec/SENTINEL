import "hash"

rule sentinel_19f8befcb035f52bf70094e6b4f5779a {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "19f8befcb035f52bf70094e6b4f5779a"
}
