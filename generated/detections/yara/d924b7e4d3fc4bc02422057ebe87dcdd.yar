import "hash"

rule sentinel_d924b7e4d3fc4bc02422057ebe87dcdd {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "otx"
  condition:
    hash.md5(0, filesize) == "d924b7e4d3fc4bc02422057ebe87dcdd"
}
