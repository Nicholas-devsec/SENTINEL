import "hash"

rule sentinel_026e6e27fe574cd05c83c82610046ba2 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "otx"
  condition:
    hash.md5(0, filesize) == "026e6e27fe574cd05c83c82610046ba2"
}
