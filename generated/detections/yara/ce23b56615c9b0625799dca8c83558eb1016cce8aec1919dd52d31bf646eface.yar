import "hash"

rule sentinel_ce23b56615c9b0625799dca8c83558eb1016cce8aec1919dd52d31bf646eface {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "ce23b56615c9b0625799dca8c83558eb1016cce8aec1919dd52d31bf646eface"
}
