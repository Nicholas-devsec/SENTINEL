import "hash"

rule sentinel_19c43bee02e049b2a6d25121e2be8782 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "19c43bee02e049b2a6d25121e2be8782"
}
