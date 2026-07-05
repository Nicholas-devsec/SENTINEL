import "hash"

rule sentinel_6f8075452b80f23418fd92e80429999ae270a6c4b88ce22cfb4223ba9853d6e1 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "6f8075452b80f23418fd92e80429999ae270a6c4b88ce22cfb4223ba9853d6e1"
}
