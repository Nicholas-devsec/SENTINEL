import "hash"

rule sentinel_0b88b880dccce959dd97041c5a816cf4 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "0b88b880dccce959dd97041c5a816cf4"
}
