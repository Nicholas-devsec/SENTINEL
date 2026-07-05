import "hash"

rule sentinel_85e816f6bd731a288f1be797a2531b0e {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "85e816f6bd731a288f1be797a2531b0e"
}
