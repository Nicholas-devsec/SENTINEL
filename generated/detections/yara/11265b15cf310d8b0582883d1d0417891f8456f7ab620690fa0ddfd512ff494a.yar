import "hash"

rule sentinel_11265b15cf310d8b0582883d1d0417891f8456f7ab620690fa0ddfd512ff494a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "11265b15cf310d8b0582883d1d0417891f8456f7ab620690fa0ddfd512ff494a"
}
