import "hash"

rule sentinel_ca4b387b37fe48b703fd32076929822d6b4b8271 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "ca4b387b37fe48b703fd32076929822d6b4b8271"
}
