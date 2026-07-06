import "hash"

rule sentinel_39c5062263296d8a39f3220574b0dcf3d959046c {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "39c5062263296d8a39f3220574b0dcf3d959046c"
}
