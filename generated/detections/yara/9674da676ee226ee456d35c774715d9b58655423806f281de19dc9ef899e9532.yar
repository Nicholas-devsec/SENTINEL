import "hash"

rule sentinel_9674da676ee226ee456d35c774715d9b58655423806f281de19dc9ef899e9532 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "9674da676ee226ee456d35c774715d9b58655423806f281de19dc9ef899e9532"
}
