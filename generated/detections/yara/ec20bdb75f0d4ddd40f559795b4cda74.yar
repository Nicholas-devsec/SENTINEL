import "hash"

rule sentinel_ec20bdb75f0d4ddd40f559795b4cda74 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ec20bdb75f0d4ddd40f559795b4cda74"
}
