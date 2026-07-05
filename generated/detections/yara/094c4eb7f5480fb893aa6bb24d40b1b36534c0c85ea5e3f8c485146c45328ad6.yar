import "hash"

rule sentinel_094c4eb7f5480fb893aa6bb24d40b1b36534c0c85ea5e3f8c485146c45328ad6 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "094c4eb7f5480fb893aa6bb24d40b1b36534c0c85ea5e3f8c485146c45328ad6"
}
