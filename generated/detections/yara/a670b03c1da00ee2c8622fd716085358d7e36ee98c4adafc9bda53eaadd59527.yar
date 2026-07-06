import "hash"

rule sentinel_a670b03c1da00ee2c8622fd716085358d7e36ee98c4adafc9bda53eaadd59527 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "a670b03c1da00ee2c8622fd716085358d7e36ee98c4adafc9bda53eaadd59527"
}
