import "hash"

rule sentinel_21317bd3996c39b8b4cb7361268a1b7a {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "21317bd3996c39b8b4cb7361268a1b7a"
}
