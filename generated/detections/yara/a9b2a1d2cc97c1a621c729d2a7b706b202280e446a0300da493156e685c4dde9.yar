import "hash"

rule sentinel_a9b2a1d2cc97c1a621c729d2a7b706b202280e446a0300da493156e685c4dde9 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "a9b2a1d2cc97c1a621c729d2a7b706b202280e446a0300da493156e685c4dde9"
}
