import "hash"

rule sentinel_1f1a89bef73e4866a198a08e750f96348ce2b82816a8353e9a8a574bfde5f491 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "1f1a89bef73e4866a198a08e750f96348ce2b82816a8353e9a8a574bfde5f491"
}
