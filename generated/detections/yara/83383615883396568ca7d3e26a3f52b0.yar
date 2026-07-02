import "hash"

rule sentinel_83383615883396568ca7d3e26a3f52b0 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "83383615883396568ca7d3e26a3f52b0"
}
