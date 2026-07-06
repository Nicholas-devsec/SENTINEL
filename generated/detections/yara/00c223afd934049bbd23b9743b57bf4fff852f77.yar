import "hash"

rule sentinel_00c223afd934049bbd23b9743b57bf4fff852f77 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "00c223afd934049bbd23b9743b57bf4fff852f77"
}
