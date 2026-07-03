import "hash"

rule sentinel_b36519598b8cd8ebcc959965db5dba1ace8d78a6 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha1(0, filesize) == "b36519598b8cd8ebcc959965db5dba1ace8d78a6"
}
