import "hash"

rule sentinel_74ceeff02f9c10bd97b9d51b912d1907 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "74ceeff02f9c10bd97b9d51b912d1907"
}
