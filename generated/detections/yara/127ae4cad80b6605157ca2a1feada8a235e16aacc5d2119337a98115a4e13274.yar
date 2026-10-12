import "hash"

rule sentinel_127ae4cad80b6605157ca2a1feada8a235e16aacc5d2119337a98115a4e13274 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "elastic_security_labs"
  condition:
    hash.sha256(0, filesize) == "127ae4cad80b6605157ca2a1feada8a235e16aacc5d2119337a98115a4e13274"
}
