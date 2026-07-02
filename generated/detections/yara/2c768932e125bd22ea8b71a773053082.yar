import "hash"

rule sentinel_2c768932e125bd22ea8b71a773053082 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "2c768932e125bd22ea8b71a773053082"
}
