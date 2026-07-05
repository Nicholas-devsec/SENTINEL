import "hash"

rule sentinel_1d0c30501bf776c01ceaa65f5691a506 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1d0c30501bf776c01ceaa65f5691a506"
}
