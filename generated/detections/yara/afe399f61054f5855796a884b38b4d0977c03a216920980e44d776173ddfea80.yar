import "hash"

rule sentinel_afe399f61054f5855796a884b38b4d0977c03a216920980e44d776173ddfea80 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "afe399f61054f5855796a884b38b4d0977c03a216920980e44d776173ddfea80"
}
