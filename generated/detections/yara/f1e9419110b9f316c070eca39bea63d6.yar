import "hash"

rule sentinel_f1e9419110b9f316c070eca39bea63d6 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "f1e9419110b9f316c070eca39bea63d6"
}
