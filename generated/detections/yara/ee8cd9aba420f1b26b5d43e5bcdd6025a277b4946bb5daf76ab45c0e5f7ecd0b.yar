import "hash"

rule sentinel_ee8cd9aba420f1b26b5d43e5bcdd6025a277b4946bb5daf76ab45c0e5f7ecd0b {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "elastic_security_labs"
  condition:
    hash.sha256(0, filesize) == "ee8cd9aba420f1b26b5d43e5bcdd6025a277b4946bb5daf76ab45c0e5f7ecd0b"
}
