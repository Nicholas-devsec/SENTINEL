import "hash"

rule sentinel_b3ad1389f9962206c973c4acefbb32f3c26cbdb884c6f01445deeeb6f9f9f8e9 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "b3ad1389f9962206c973c4acefbb32f3c26cbdb884c6f01445deeeb6f9f9f8e9"
}
