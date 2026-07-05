import "hash"

rule sentinel_4778be442a687b1a454a83b070c526a3 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "4778be442a687b1a454a83b070c526a3"
}
