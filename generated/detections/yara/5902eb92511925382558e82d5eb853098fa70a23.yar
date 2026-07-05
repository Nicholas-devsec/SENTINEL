import "hash"

rule sentinel_5902eb92511925382558e82d5eb853098fa70a23 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "5902eb92511925382558e82d5eb853098fa70a23"
}
