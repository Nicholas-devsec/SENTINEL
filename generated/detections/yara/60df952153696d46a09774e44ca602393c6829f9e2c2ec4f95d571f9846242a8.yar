import "hash"

rule sentinel_60df952153696d46a09774e44ca602393c6829f9e2c2ec4f95d571f9846242a8 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "60df952153696d46a09774e44ca602393c6829f9e2c2ec4f95d571f9846242a8"
}
