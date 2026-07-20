import "hash"

rule sentinel_b0c4fe17a83df1621ce3db824684bb55 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "b0c4fe17a83df1621ce3db824684bb55"
}
