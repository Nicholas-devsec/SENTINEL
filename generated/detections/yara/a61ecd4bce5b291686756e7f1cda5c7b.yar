import "hash"

rule sentinel_a61ecd4bce5b291686756e7f1cda5c7b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "a61ecd4bce5b291686756e7f1cda5c7b"
}
