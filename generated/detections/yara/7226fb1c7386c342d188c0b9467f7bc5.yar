import "hash"

rule sentinel_7226fb1c7386c342d188c0b9467f7bc5 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "7226fb1c7386c342d188c0b9467f7bc5"
}
