import "hash"

rule sentinel_2b512f6c393edad89a89ecafe26cd23b71cfdd271c10522f8dba98997ebf39bb {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "2b512f6c393edad89a89ecafe26cd23b71cfdd271c10522f8dba98997ebf39bb"
}
