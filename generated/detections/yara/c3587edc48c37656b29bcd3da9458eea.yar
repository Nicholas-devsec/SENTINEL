import "hash"

rule sentinel_c3587edc48c37656b29bcd3da9458eea {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "discovery:cyberpress.org"
  condition:
    hash.md5(0, filesize) == "c3587edc48c37656b29bcd3da9458eea"
}
