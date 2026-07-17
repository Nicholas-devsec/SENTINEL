import "hash"

rule sentinel_3eab3ec9304aa26081358330491d3cfeb55cc245 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha1(0, filesize) == "3eab3ec9304aa26081358330491d3cfeb55cc245"
}
