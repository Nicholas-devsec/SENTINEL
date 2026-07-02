import "hash"

rule sentinel_54415e8a8d8e1ad25fdb246d9dfd50c76dce805a47b92d84539f23d14f6ee31b {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "54415e8a8d8e1ad25fdb246d9dfd50c76dce805a47b92d84539f23d14f6ee31b"
}
