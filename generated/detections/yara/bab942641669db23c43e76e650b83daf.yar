import "hash"

rule sentinel_bab942641669db23c43e76e650b83daf {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "bab942641669db23c43e76e650b83daf"
}
