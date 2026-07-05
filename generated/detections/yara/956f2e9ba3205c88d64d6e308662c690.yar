import "hash"

rule sentinel_956f2e9ba3205c88d64d6e308662c690 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "956f2e9ba3205c88d64d6e308662c690"
}
