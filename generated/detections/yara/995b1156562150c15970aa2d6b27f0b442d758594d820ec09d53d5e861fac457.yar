import "hash"

rule sentinel_995b1156562150c15970aa2d6b27f0b442d758594d820ec09d53d5e861fac457 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "995b1156562150c15970aa2d6b27f0b442d758594d820ec09d53d5e861fac457"
}
