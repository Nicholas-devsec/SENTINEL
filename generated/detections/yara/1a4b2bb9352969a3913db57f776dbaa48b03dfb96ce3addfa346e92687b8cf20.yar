import "hash"

rule sentinel_1a4b2bb9352969a3913db57f776dbaa48b03dfb96ce3addfa346e92687b8cf20 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "1a4b2bb9352969a3913db57f776dbaa48b03dfb96ce3addfa346e92687b8cf20"
}
