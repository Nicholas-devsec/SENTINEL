import "hash"

rule sentinel_63737ab4e5b5310e0468b3707e749c53609e9962ed0e4a19ab1ce2a358dcd3a4 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "63737ab4e5b5310e0468b3707e749c53609e9962ed0e4a19ab1ce2a358dcd3a4"
}
