import "hash"

rule sentinel_bb551faff31c0a2c073b8a8cde34b41b6aed6e3aa7ca190e4764fdbc037be2c3 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "bb551faff31c0a2c073b8a8cde34b41b6aed6e3aa7ca190e4764fdbc037be2c3"
}
