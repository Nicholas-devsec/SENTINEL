import "hash"

rule sentinel_1aa4445c35c8bfb52304fcd252451843ff671d115c9e75a123043dc79ae9cdc6 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "1aa4445c35c8bfb52304fcd252451843ff671d115c9e75a123043dc79ae9cdc6"
}
