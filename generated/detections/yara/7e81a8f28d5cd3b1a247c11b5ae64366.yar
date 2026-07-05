import "hash"

rule sentinel_7e81a8f28d5cd3b1a247c11b5ae64366 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "7e81a8f28d5cd3b1a247c11b5ae64366"
}
