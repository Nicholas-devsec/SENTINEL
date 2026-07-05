import "hash"

rule sentinel_5ee634e2b12edba1e2c403fb9ba3e3fd {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "5ee634e2b12edba1e2c403fb9ba3e3fd"
}
