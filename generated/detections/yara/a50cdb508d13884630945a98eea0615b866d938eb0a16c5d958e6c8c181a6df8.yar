import "hash"

rule sentinel_a50cdb508d13884630945a98eea0615b866d938eb0a16c5d958e6c8c181a6df8 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "elastic_security_labs"
  condition:
    hash.sha256(0, filesize) == "a50cdb508d13884630945a98eea0615b866d938eb0a16c5d958e6c8c181a6df8"
}
