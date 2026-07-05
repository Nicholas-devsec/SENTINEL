import "hash"

rule sentinel_432fdcf8fc43c3871c3346bb2aeb3de2 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "432fdcf8fc43c3871c3346bb2aeb3de2"
}
