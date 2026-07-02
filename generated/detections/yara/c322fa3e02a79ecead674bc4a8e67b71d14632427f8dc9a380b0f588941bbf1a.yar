import "hash"

rule sentinel_c322fa3e02a79ecead674bc4a8e67b71d14632427f8dc9a380b0f588941bbf1a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "c322fa3e02a79ecead674bc4a8e67b71d14632427f8dc9a380b0f588941bbf1a"
}
