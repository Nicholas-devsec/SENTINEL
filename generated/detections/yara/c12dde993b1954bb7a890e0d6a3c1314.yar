import "hash"

rule sentinel_c12dde993b1954bb7a890e0d6a3c1314 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "c12dde993b1954bb7a890e0d6a3c1314"
}
