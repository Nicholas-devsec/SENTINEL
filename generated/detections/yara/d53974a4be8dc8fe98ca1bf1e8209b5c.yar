import "hash"

rule sentinel_d53974a4be8dc8fe98ca1bf1e8209b5c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "d53974a4be8dc8fe98ca1bf1e8209b5c"
}
