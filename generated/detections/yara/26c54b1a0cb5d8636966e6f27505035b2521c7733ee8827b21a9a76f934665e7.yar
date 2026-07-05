import "hash"

rule sentinel_26c54b1a0cb5d8636966e6f27505035b2521c7733ee8827b21a9a76f934665e7 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "26c54b1a0cb5d8636966e6f27505035b2521c7733ee8827b21a9a76f934665e7"
}
