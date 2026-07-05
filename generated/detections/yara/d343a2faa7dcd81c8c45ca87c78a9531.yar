import "hash"

rule sentinel_d343a2faa7dcd81c8c45ca87c78a9531 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "d343a2faa7dcd81c8c45ca87c78a9531"
}
