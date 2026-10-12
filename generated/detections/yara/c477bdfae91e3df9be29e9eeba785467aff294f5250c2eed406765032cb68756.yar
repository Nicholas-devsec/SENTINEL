import "hash"

rule sentinel_c477bdfae91e3df9be29e9eeba785467aff294f5250c2eed406765032cb68756 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "c477bdfae91e3df9be29e9eeba785467aff294f5250c2eed406765032cb68756"
}
