import "hash"

rule sentinel_dc182edfa40394392a1ada4925989e994a3db462 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "dc182edfa40394392a1ada4925989e994a3db462"
}
