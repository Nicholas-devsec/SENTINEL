import "hash"

rule sentinel_91bec80a496ade780dc7ad31b15a3bd41850abc1 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "91bec80a496ade780dc7ad31b15a3bd41850abc1"
}
