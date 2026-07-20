import "hash"

rule sentinel_b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0"
}
