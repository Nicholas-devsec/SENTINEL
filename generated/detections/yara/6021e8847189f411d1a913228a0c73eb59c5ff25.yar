import "hash"

rule sentinel_6021e8847189f411d1a913228a0c73eb59c5ff25 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "6021e8847189f411d1a913228a0c73eb59c5ff25"
}
