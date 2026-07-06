import "hash"

rule sentinel_5053320a66a5c4989c44a932a8720b7d {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "5053320a66a5c4989c44a932a8720b7d"
}
