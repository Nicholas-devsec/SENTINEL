import "hash"

rule sentinel_3f31aee0948d16f8d64bf6bec69a4331099993e502b11bfc56b2c0112024489d {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "3f31aee0948d16f8d64bf6bec69a4331099993e502b11bfc56b2c0112024489d"
}
