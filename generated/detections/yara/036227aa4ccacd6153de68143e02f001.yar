import "hash"

rule sentinel_036227aa4ccacd6153de68143e02f001 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "036227aa4ccacd6153de68143e02f001"
}
