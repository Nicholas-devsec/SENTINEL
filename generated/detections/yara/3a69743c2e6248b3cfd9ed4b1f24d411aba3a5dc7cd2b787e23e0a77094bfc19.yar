import "hash"

rule sentinel_3a69743c2e6248b3cfd9ed4b1f24d411aba3a5dc7cd2b787e23e0a77094bfc19 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "3a69743c2e6248b3cfd9ed4b1f24d411aba3a5dc7cd2b787e23e0a77094bfc19"
}
