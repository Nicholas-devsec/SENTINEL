import "hash"

rule sentinel_e218b8685c58080ff42dd0c8af154849 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "e218b8685c58080ff42dd0c8af154849"
}
