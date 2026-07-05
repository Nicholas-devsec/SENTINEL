import "hash"

rule sentinel_c559cc68986933200fd5d9e4388e2f58 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "discovery:cyberpress.org"
  condition:
    hash.md5(0, filesize) == "c559cc68986933200fd5d9e4388e2f58"
}
