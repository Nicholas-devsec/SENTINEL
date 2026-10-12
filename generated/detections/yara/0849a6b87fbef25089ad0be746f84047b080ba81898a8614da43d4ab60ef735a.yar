import "hash"

rule sentinel_0849a6b87fbef25089ad0be746f84047b080ba81898a8614da43d4ab60ef735a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "0849a6b87fbef25089ad0be746f84047b080ba81898a8614da43d4ab60ef735a"
}
