import "hash"

rule sentinel_1054c11b6ab75a0d4477689a8100159620f116d7 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "1054c11b6ab75a0d4477689a8100159620f116d7"
}
