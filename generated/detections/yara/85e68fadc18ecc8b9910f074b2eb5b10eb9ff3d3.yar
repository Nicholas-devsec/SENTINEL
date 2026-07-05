import "hash"

rule sentinel_85e68fadc18ecc8b9910f074b2eb5b10eb9ff3d3 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "85e68fadc18ecc8b9910f074b2eb5b10eb9ff3d3"
}
