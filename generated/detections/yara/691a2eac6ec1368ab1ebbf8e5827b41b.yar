import "hash"

rule sentinel_691a2eac6ec1368ab1ebbf8e5827b41b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "691a2eac6ec1368ab1ebbf8e5827b41b"
}
