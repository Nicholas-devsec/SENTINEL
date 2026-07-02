import "hash"

rule sentinel_e64428142676e50e4d1df72e11a785e68c953f55 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "e64428142676e50e4d1df72e11a785e68c953f55"
}
