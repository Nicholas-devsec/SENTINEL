import "hash"

rule sentinel_0b4d962eef2d06abfe08a8cd0b15edd224d4fae0b57d708aebd77d99667616d5 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "0b4d962eef2d06abfe08a8cd0b15edd224d4fae0b57d708aebd77d99667616d5"
}
