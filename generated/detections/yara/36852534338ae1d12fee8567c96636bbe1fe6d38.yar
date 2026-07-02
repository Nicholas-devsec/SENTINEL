import "hash"

rule sentinel_36852534338ae1d12fee8567c96636bbe1fe6d38 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "36852534338ae1d12fee8567c96636bbe1fe6d38"
}
