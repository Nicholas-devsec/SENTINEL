import "hash"

rule sentinel_a82006f49debbb71c624429efed67e58 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "a82006f49debbb71c624429efed67e58"
}
