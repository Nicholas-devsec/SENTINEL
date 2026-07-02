import "hash"

rule sentinel_9fd59b56ea2c757ee6f2b8fddc45f7d36efeca135cee1c92511799c85351ebf3 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "9fd59b56ea2c757ee6f2b8fddc45f7d36efeca135cee1c92511799c85351ebf3"
}
