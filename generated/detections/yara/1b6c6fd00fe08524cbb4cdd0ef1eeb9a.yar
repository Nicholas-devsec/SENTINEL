import "hash"

rule sentinel_1b6c6fd00fe08524cbb4cdd0ef1eeb9a {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1b6c6fd00fe08524cbb4cdd0ef1eeb9a"
}
