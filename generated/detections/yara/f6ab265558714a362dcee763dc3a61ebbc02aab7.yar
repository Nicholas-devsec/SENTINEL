import "hash"

rule sentinel_f6ab265558714a362dcee763dc3a61ebbc02aab7 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "f6ab265558714a362dcee763dc3a61ebbc02aab7"
}
