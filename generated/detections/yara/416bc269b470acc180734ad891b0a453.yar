import "hash"

rule sentinel_416bc269b470acc180734ad891b0a453 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "416bc269b470acc180734ad891b0a453"
}
