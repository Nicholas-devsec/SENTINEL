import "hash"

rule sentinel_bb3a7fd3b9cbaa214cd086dc6fb09b1cba35f3d8 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "bb3a7fd3b9cbaa214cd086dc6fb09b1cba35f3d8"
}
