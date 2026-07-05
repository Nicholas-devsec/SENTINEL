import "hash"

rule sentinel_eb4c2dc7db21d6a8a889c74c7b90eaac0e095205063ae3e348a400e253c6bdd8 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "eb4c2dc7db21d6a8a889c74c7b90eaac0e095205063ae3e348a400e253c6bdd8"
}
