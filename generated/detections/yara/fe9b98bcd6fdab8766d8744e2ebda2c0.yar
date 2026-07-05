import "hash"

rule sentinel_fe9b98bcd6fdab8766d8744e2ebda2c0 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "fe9b98bcd6fdab8766d8744e2ebda2c0"
}
