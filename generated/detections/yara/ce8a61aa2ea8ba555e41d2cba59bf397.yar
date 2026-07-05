import "hash"

rule sentinel_ce8a61aa2ea8ba555e41d2cba59bf397 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ce8a61aa2ea8ba555e41d2cba59bf397"
}
