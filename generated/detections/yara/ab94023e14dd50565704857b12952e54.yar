import "hash"

rule sentinel_ab94023e14dd50565704857b12952e54 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ab94023e14dd50565704857b12952e54"
}
