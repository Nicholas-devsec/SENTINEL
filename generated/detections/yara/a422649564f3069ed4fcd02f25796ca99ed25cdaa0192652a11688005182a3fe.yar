import "hash"

rule sentinel_a422649564f3069ed4fcd02f25796ca99ed25cdaa0192652a11688005182a3fe {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "a422649564f3069ed4fcd02f25796ca99ed25cdaa0192652a11688005182a3fe"
}
