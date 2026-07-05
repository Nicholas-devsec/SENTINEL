import "hash"

rule sentinel_3a87b24c57f5a83bfadca1e83360618f89f8d53c1bfccb1a8c005547877feac2 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "3a87b24c57f5a83bfadca1e83360618f89f8d53c1bfccb1a8c005547877feac2"
}
