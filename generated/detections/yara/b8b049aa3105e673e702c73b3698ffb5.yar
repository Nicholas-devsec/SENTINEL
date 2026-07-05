import "hash"

rule sentinel_b8b049aa3105e673e702c73b3698ffb5 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "b8b049aa3105e673e702c73b3698ffb5"
}
