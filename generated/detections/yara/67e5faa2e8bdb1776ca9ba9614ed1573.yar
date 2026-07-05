import "hash"

rule sentinel_67e5faa2e8bdb1776ca9ba9614ed1573 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "67e5faa2e8bdb1776ca9ba9614ed1573"
}
