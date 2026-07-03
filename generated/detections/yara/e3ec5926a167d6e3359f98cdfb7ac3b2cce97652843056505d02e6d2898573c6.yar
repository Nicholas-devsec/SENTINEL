import "hash"

rule sentinel_e3ec5926a167d6e3359f98cdfb7ac3b2cce97652843056505d02e6d2898573c6 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "e3ec5926a167d6e3359f98cdfb7ac3b2cce97652843056505d02e6d2898573c6"
}
