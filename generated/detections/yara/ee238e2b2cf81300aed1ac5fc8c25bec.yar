import "hash"

rule sentinel_ee238e2b2cf81300aed1ac5fc8c25bec {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ee238e2b2cf81300aed1ac5fc8c25bec"
}
