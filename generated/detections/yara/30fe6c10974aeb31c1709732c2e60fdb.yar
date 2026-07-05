import "hash"

rule sentinel_30fe6c10974aeb31c1709732c2e60fdb {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "30fe6c10974aeb31c1709732c2e60fdb"
}
