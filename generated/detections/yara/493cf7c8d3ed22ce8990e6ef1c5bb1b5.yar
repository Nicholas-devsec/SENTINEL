import "hash"

rule sentinel_493cf7c8d3ed22ce8990e6ef1c5bb1b5 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "493cf7c8d3ed22ce8990e6ef1c5bb1b5"
}
