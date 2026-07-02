import "hash"

rule sentinel_e11bb364c56bf0880c2402744dbb4d83 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "e11bb364c56bf0880c2402744dbb4d83"
}
