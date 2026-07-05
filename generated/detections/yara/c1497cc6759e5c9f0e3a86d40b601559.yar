import "hash"

rule sentinel_c1497cc6759e5c9f0e3a86d40b601559 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "c1497cc6759e5c9f0e3a86d40b601559"
}
