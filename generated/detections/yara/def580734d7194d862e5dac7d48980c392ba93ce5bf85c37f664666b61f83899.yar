import "hash"

rule sentinel_def580734d7194d862e5dac7d48980c392ba93ce5bf85c37f664666b61f83899 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "def580734d7194d862e5dac7d48980c392ba93ce5bf85c37f664666b61f83899"
}
