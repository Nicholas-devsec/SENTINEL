import "hash"

rule sentinel_780a6443312a97c4c04955d21f767bd1 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "780a6443312a97c4c04955d21f767bd1"
}
