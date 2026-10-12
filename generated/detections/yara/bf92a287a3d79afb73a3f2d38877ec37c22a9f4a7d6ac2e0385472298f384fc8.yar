import "hash"

rule sentinel_bf92a287a3d79afb73a3f2d38877ec37c22a9f4a7d6ac2e0385472298f384fc8 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "bf92a287a3d79afb73a3f2d38877ec37c22a9f4a7d6ac2e0385472298f384fc8"
}
