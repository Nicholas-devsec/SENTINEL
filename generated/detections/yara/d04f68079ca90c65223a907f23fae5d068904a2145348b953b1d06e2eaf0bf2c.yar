import "hash"

rule sentinel_d04f68079ca90c65223a907f23fae5d068904a2145348b953b1d06e2eaf0bf2c {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "d04f68079ca90c65223a907f23fae5d068904a2145348b953b1d06e2eaf0bf2c"
}
