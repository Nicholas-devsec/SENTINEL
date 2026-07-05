import "hash"

rule sentinel_9b3dce50e1056e6eca0faee733c33f35 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "9b3dce50e1056e6eca0faee733c33f35"
}
