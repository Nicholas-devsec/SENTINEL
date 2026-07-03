import "hash"

rule sentinel_5e16dd79001f2faba4569e2abd5b19c0 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "otx"
  condition:
    hash.md5(0, filesize) == "5e16dd79001f2faba4569e2abd5b19c0"
}
