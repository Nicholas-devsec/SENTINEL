import "hash"

rule sentinel_05fe6a71add6db59c0457698f4bc7a56287ab43b {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "05fe6a71add6db59c0457698f4bc7a56287ab43b"
}
