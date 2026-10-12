import "hash"

rule sentinel_debe871710268e7bb770b72c6772f2e0b8bd40a22b2eabf4b6556eaba2d71057 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "debe871710268e7bb770b72c6772f2e0b8bd40a22b2eabf4b6556eaba2d71057"
}
