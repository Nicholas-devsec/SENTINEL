import "hash"

rule sentinel_128f48d4dda439d084c90f283d3bd9293a8d22bd86b9b5e2c57afaf5e487243b {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "128f48d4dda439d084c90f283d3bd9293a8d22bd86b9b5e2c57afaf5e487243b"
}
