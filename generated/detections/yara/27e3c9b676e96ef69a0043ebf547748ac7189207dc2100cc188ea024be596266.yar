import "hash"

rule sentinel_27e3c9b676e96ef69a0043ebf547748ac7189207dc2100cc188ea024be596266 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "27e3c9b676e96ef69a0043ebf547748ac7189207dc2100cc188ea024be596266"
}
