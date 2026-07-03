import "hash"

rule sentinel_e291f991d4bd616203b291a36121dc8b0c15f509 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha1(0, filesize) == "e291f991d4bd616203b291a36121dc8b0c15f509"
}
