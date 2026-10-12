import "hash"

rule sentinel_47d321c1a232e5cdd1e39a06dadbd79114dc1a2f0f8eac289e6b653a5d126f95 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "47d321c1a232e5cdd1e39a06dadbd79114dc1a2f0f8eac289e6b653a5d126f95"
}
