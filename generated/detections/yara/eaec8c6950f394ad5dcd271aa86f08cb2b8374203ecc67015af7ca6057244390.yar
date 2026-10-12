import "hash"

rule sentinel_eaec8c6950f394ad5dcd271aa86f08cb2b8374203ecc67015af7ca6057244390 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "eaec8c6950f394ad5dcd271aa86f08cb2b8374203ecc67015af7ca6057244390"
}
