import "hash"

rule sentinel_9a0e23765cfcdfe7e28c9be6f458c620 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "9a0e23765cfcdfe7e28c9be6f458c620"
}
