import "hash"

rule sentinel_8cd18949fe86667303cd19c683310d55 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "8cd18949fe86667303cd19c683310d55"
}
