import "hash"

rule sentinel_36d46ac7123e0cef04f179d88e590891c7e7c64ec5a77df4512cb485e40286da {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "36d46ac7123e0cef04f179d88e590891c7e7c64ec5a77df4512cb485e40286da"
}
