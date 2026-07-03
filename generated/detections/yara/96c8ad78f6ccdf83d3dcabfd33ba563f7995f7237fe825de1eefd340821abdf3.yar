import "hash"

rule sentinel_96c8ad78f6ccdf83d3dcabfd33ba563f7995f7237fe825de1eefd340821abdf3 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "96c8ad78f6ccdf83d3dcabfd33ba563f7995f7237fe825de1eefd340821abdf3"
}
