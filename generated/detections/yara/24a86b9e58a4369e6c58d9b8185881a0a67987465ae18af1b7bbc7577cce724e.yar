import "hash"

rule sentinel_24a86b9e58a4369e6c58d9b8185881a0a67987465ae18af1b7bbc7577cce724e {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "24a86b9e58a4369e6c58d9b8185881a0a67987465ae18af1b7bbc7577cce724e"
}
