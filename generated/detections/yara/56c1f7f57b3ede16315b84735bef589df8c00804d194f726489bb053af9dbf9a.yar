import "hash"

rule sentinel_56c1f7f57b3ede16315b84735bef589df8c00804d194f726489bb053af9dbf9a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "56c1f7f57b3ede16315b84735bef589df8c00804d194f726489bb053af9dbf9a"
}
