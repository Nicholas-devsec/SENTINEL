import "hash"

rule sentinel_b3352b42432dedc4a519f011dc8b5d5a {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "discovery:cyberpress.org"
  condition:
    hash.md5(0, filesize) == "b3352b42432dedc4a519f011dc8b5d5a"
}
