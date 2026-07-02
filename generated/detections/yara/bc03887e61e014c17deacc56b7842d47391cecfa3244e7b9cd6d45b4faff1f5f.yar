import "hash"

rule sentinel_bc03887e61e014c17deacc56b7842d47391cecfa3244e7b9cd6d45b4faff1f5f {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "bc03887e61e014c17deacc56b7842d47391cecfa3244e7b9cd6d45b4faff1f5f"
}
