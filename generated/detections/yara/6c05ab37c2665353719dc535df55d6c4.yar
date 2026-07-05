import "hash"

rule sentinel_6c05ab37c2665353719dc535df55d6c4 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6c05ab37c2665353719dc535df55d6c4"
}
