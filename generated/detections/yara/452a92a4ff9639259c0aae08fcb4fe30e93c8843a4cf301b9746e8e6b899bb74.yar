import "hash"

rule sentinel_452a92a4ff9639259c0aae08fcb4fe30e93c8843a4cf301b9746e8e6b899bb74 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "452a92a4ff9639259c0aae08fcb4fe30e93c8843a4cf301b9746e8e6b899bb74"
}
