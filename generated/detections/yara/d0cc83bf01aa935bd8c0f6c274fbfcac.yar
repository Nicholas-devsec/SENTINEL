import "hash"

rule sentinel_d0cc83bf01aa935bd8c0f6c274fbfcac {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "d0cc83bf01aa935bd8c0f6c274fbfcac"
}
