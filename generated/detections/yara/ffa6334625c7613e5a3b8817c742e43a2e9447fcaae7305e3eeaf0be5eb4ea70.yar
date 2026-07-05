import "hash"

rule sentinel_ffa6334625c7613e5a3b8817c742e43a2e9447fcaae7305e3eeaf0be5eb4ea70 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "ffa6334625c7613e5a3b8817c742e43a2e9447fcaae7305e3eeaf0be5eb4ea70"
}
