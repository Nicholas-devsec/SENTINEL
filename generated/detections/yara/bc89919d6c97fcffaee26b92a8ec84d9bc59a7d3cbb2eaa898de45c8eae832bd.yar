import "hash"

rule sentinel_bc89919d6c97fcffaee26b92a8ec84d9bc59a7d3cbb2eaa898de45c8eae832bd {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "bc89919d6c97fcffaee26b92a8ec84d9bc59a7d3cbb2eaa898de45c8eae832bd"
}
