import "hash"

rule sentinel_be6010d8bddef29ebbf3c8bb28f19517 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "be6010d8bddef29ebbf3c8bb28f19517"
}
