import "hash"

rule sentinel_8c21b2fbded2faeb6db2e7a20c513cdb {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "8c21b2fbded2faeb6db2e7a20c513cdb"
}
