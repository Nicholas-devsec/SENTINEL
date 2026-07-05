import "hash"

rule sentinel_36c34ad170bc6ab9e54bb55d1b9b1cf33387c436 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "36c34ad170bc6ab9e54bb55d1b9b1cf33387c436"
}
