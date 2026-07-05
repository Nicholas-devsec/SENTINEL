import "hash"

rule sentinel_5f5c56a6195e2e15167660416f442d3b10b8eff1 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "5f5c56a6195e2e15167660416f442d3b10b8eff1"
}
