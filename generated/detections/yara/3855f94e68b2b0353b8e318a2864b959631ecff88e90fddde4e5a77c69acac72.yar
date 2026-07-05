import "hash"

rule sentinel_3855f94e68b2b0353b8e318a2864b959631ecff88e90fddde4e5a77c69acac72 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "3855f94e68b2b0353b8e318a2864b959631ecff88e90fddde4e5a77c69acac72"
}
