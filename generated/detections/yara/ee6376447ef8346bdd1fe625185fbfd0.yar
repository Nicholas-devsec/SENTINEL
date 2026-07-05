import "hash"

rule sentinel_ee6376447ef8346bdd1fe625185fbfd0 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ee6376447ef8346bdd1fe625185fbfd0"
}
