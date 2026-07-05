import "hash"

rule sentinel_f2bab102784860e65cd488387e42ca50 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "f2bab102784860e65cd488387e42ca50"
}
