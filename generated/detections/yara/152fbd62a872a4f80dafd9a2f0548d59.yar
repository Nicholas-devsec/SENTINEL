import "hash"

rule sentinel_152fbd62a872a4f80dafd9a2f0548d59 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "152fbd62a872a4f80dafd9a2f0548d59"
}
