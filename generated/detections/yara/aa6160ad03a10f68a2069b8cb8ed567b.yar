import "hash"

rule sentinel_aa6160ad03a10f68a2069b8cb8ed567b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "aa6160ad03a10f68a2069b8cb8ed567b"
}
