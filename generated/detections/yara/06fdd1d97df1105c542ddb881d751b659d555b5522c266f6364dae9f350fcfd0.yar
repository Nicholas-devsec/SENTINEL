import "hash"

rule sentinel_06fdd1d97df1105c542ddb881d751b659d555b5522c266f6364dae9f350fcfd0 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "06fdd1d97df1105c542ddb881d751b659d555b5522c266f6364dae9f350fcfd0"
}
