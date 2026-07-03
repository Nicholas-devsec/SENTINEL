import "hash"

rule sentinel_b7d50d0406afcd2efd87bf3bf8c4211719ba9817dd2e0ad62af10c933e765e28 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "b7d50d0406afcd2efd87bf3bf8c4211719ba9817dd2e0ad62af10c933e765e28"
}
