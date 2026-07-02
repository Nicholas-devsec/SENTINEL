import "hash"

rule sentinel_f4f3450d5e13bb3e8a1809bf7d0528cf2387df80 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "f4f3450d5e13bb3e8a1809bf7d0528cf2387df80"
}
