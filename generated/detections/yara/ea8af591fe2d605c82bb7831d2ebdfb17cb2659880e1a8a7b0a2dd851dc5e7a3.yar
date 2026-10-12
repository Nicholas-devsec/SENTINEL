import "hash"

rule sentinel_ea8af591fe2d605c82bb7831d2ebdfb17cb2659880e1a8a7b0a2dd851dc5e7a3 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "ea8af591fe2d605c82bb7831d2ebdfb17cb2659880e1a8a7b0a2dd851dc5e7a3"
}
