import "hash"

rule sentinel_6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:www.microsoft.com"
  condition:
    hash.sha256(0, filesize) == "6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71"
}
