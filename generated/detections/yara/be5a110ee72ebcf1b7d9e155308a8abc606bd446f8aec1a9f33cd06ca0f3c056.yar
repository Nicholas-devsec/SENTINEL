import "hash"

rule sentinel_be5a110ee72ebcf1b7d9e155308a8abc606bd446f8aec1a9f33cd06ca0f3c056 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "be5a110ee72ebcf1b7d9e155308a8abc606bd446f8aec1a9f33cd06ca0f3c056"
}
