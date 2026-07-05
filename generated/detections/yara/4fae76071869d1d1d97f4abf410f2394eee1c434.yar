import "hash"

rule sentinel_4fae76071869d1d1d97f4abf410f2394eee1c434 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "4fae76071869d1d1d97f4abf410f2394eee1c434"
}
