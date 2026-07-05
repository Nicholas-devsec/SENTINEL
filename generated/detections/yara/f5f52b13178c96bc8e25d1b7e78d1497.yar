import "hash"

rule sentinel_f5f52b13178c96bc8e25d1b7e78d1497 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "f5f52b13178c96bc8e25d1b7e78d1497"
}
