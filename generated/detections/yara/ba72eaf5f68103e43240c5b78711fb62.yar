import "hash"

rule sentinel_ba72eaf5f68103e43240c5b78711fb62 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ba72eaf5f68103e43240c5b78711fb62"
}
