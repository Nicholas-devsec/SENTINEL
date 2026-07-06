import "hash"

rule sentinel_aded3c60373e26d7e9648cdb78c280de {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "aded3c60373e26d7e9648cdb78c280de"
}
