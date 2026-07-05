import "hash"

rule sentinel_13a208ad6b172ec37bfe5dacaf0b96fe {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "13a208ad6b172ec37bfe5dacaf0b96fe"
}
