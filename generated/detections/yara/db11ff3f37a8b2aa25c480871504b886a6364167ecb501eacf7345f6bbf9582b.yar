import "hash"

rule sentinel_db11ff3f37a8b2aa25c480871504b886a6364167ecb501eacf7345f6bbf9582b {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "db11ff3f37a8b2aa25c480871504b886a6364167ecb501eacf7345f6bbf9582b"
}
