import "hash"

rule sentinel_0bf7db6f6f756c1ce4346ac88727d04c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "0bf7db6f6f756c1ce4346ac88727d04c"
}
