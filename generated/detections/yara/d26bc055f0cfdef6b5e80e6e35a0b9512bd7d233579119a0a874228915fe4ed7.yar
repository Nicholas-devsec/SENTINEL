import "hash"

rule sentinel_d26bc055f0cfdef6b5e80e6e35a0b9512bd7d233579119a0a874228915fe4ed7 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "d26bc055f0cfdef6b5e80e6e35a0b9512bd7d233579119a0a874228915fe4ed7"
}
