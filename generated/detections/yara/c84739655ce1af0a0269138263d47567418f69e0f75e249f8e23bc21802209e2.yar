import "hash"

rule sentinel_c84739655ce1af0a0269138263d47567418f69e0f75e249f8e23bc21802209e2 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "gbhackers_blog"
  condition:
    hash.sha256(0, filesize) == "c84739655ce1af0a0269138263d47567418f69e0f75e249f8e23bc21802209e2"
}
