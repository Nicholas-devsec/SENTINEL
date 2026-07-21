import "hash"

rule sentinel_4f1773a1228e2c009cbcf61e9e550e01 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "otx"
  condition:
    hash.md5(0, filesize) == "4f1773a1228e2c009cbcf61e9e550e01"
}
