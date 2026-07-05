import "hash"

rule sentinel_b02174f08e5f467415dbd2a8e61404c8a370e2adcbfaa68bd8e3b52ad68097b4 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "b02174f08e5f467415dbd2a8e61404c8a370e2adcbfaa68bd8e3b52ad68097b4"
}
