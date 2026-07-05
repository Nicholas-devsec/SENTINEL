import "hash"

rule sentinel_20d47fa34fb6c5841bbebea4796b7b9fcc3f6920ef9d3be0530978f0cbc6e4d7 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "20d47fa34fb6c5841bbebea4796b7b9fcc3f6920ef9d3be0530978f0cbc6e4d7"
}
