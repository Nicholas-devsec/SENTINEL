import "hash"

rule sentinel_3d30d0eb3484b37f2dc2bf9a804b0156 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "3d30d0eb3484b37f2dc2bf9a804b0156"
}
