import "hash"

rule sentinel_7c72f6d08c1165bd5bf9ef8ffadf1705 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "7c72f6d08c1165bd5bf9ef8ffadf1705"
}
