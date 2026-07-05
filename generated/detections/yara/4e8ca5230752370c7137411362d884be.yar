import "hash"

rule sentinel_4e8ca5230752370c7137411362d884be {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "4e8ca5230752370c7137411362d884be"
}
