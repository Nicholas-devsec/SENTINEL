import "hash"

rule sentinel_1a5c04fc48b962864b86682f54294031 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1a5c04fc48b962864b86682f54294031"
}
