import "hash"

rule sentinel_28fb34a8dc7b82c4820891134e6f19941e502dc7 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "28fb34a8dc7b82c4820891134e6f19941e502dc7"
}
