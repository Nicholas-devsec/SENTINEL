import "hash"

rule sentinel_ef1df6880f861de62d8b30cd3623f410 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ef1df6880f861de62d8b30cd3623f410"
}
