import "hash"

rule sentinel_f3ed0bcc692555fea83c6556abaa5dc2b91bcb38 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha1(0, filesize) == "f3ed0bcc692555fea83c6556abaa5dc2b91bcb38"
}
