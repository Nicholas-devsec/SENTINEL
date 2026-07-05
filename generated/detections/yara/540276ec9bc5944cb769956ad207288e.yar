import "hash"

rule sentinel_540276ec9bc5944cb769956ad207288e {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "540276ec9bc5944cb769956ad207288e"
}
