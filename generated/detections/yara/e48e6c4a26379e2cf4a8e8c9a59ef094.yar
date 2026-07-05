import "hash"

rule sentinel_e48e6c4a26379e2cf4a8e8c9a59ef094 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "e48e6c4a26379e2cf4a8e8c9a59ef094"
}
