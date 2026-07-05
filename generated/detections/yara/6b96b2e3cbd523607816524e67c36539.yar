import "hash"

rule sentinel_6b96b2e3cbd523607816524e67c36539 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6b96b2e3cbd523607816524e67c36539"
}
