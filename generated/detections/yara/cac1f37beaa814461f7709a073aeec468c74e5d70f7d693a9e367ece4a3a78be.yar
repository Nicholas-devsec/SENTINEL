import "hash"

rule sentinel_cac1f37beaa814461f7709a073aeec468c74e5d70f7d693a9e367ece4a3a78be {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "cac1f37beaa814461f7709a073aeec468c74e5d70f7d693a9e367ece4a3a78be"
}
