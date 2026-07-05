import "hash"

rule sentinel_69446d7192ce7e5737bd9f7cbc7ca74a {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "69446d7192ce7e5737bd9f7cbc7ca74a"
}
