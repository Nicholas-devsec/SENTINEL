import "hash"

rule sentinel_57cdc5b17c4bf3636d7be3aad05e3a22bbd50f6b {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "57cdc5b17c4bf3636d7be3aad05e3a22bbd50f6b"
}
