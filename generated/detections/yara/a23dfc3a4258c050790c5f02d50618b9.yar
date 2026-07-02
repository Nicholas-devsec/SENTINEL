import "hash"

rule sentinel_a23dfc3a4258c050790c5f02d50618b9 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "a23dfc3a4258c050790c5f02d50618b9"
}
