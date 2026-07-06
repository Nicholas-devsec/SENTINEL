import "hash"

rule sentinel_f612967f1314ebf94d636fb9dc20e84e {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "f612967f1314ebf94d636fb9dc20e84e"
}
