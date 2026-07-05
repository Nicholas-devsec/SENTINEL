import "hash"

rule sentinel_63e36739580577e2e5d9677f03b1ebb1 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "63e36739580577e2e5d9677f03b1ebb1"
}
