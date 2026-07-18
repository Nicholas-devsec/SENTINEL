import "hash"

rule sentinel_5cdb6a3810a5148518252110e51655297a6a9832f254f65f804b5a6fad1e3259 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "5cdb6a3810a5148518252110e51655297a6a9832f254f65f804b5a6fad1e3259"
}
