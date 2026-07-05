import "hash"

rule sentinel_25f568d7838e70b4f8dafadd74a7d7fc {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "25f568d7838e70b4f8dafadd74a7d7fc"
}
