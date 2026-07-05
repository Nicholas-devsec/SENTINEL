import "hash"

rule sentinel_c2a388115e47c2ffb0f65ec4ef28f8c961e9c37ade10b39dd920fa5909824e7f {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "c2a388115e47c2ffb0f65ec4ef28f8c961e9c37ade10b39dd920fa5909824e7f"
}
