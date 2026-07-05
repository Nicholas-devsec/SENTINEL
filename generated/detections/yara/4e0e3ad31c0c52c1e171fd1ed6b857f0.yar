import "hash"

rule sentinel_4e0e3ad31c0c52c1e171fd1ed6b857f0 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "4e0e3ad31c0c52c1e171fd1ed6b857f0"
}
