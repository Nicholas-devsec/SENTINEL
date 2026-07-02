import "hash"

rule sentinel_5d682fcbc666cd2426c45b11fa94f16b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "5d682fcbc666cd2426c45b11fa94f16b"
}
