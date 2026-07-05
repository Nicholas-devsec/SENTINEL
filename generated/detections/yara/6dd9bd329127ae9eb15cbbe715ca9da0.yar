import "hash"

rule sentinel_6dd9bd329127ae9eb15cbbe715ca9da0 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6dd9bd329127ae9eb15cbbe715ca9da0"
}
