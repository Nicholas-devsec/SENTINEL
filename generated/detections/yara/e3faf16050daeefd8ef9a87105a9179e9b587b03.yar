import "hash"

rule sentinel_e3faf16050daeefd8ef9a87105a9179e9b587b03 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "e3faf16050daeefd8ef9a87105a9179e9b587b03"
}
