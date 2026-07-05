import "hash"

rule sentinel_94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00"
}
