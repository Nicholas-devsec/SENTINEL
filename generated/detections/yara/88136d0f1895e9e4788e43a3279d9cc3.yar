import "hash"

rule sentinel_88136d0f1895e9e4788e43a3279d9cc3 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "88136d0f1895e9e4788e43a3279d9cc3"
}
