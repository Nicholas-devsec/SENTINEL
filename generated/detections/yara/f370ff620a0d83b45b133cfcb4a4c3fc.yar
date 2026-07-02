import "hash"

rule sentinel_f370ff620a0d83b45b133cfcb4a4c3fc {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "f370ff620a0d83b45b133cfcb4a4c3fc"
}
