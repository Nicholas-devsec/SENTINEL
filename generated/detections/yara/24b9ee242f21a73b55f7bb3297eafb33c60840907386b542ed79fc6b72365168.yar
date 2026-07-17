import "hash"

rule sentinel_24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:www.microsoft.com"
  condition:
    hash.sha256(0, filesize) == "24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168"
}
