import "hash"

rule sentinel_70fef9fd6e351f4d53cfeee8dcdfcd99 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "70fef9fd6e351f4d53cfeee8dcdfcd99"
}
