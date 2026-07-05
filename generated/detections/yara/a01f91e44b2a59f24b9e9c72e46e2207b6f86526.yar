import "hash"

rule sentinel_a01f91e44b2a59f24b9e9c72e46e2207b6f86526 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "a01f91e44b2a59f24b9e9c72e46e2207b6f86526"
}
