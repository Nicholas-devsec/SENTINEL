import "hash"

rule sentinel_9c0a88ea53c4e0324157542385a1d342101feb51cf7b8cf76e9441376f1f522a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "9c0a88ea53c4e0324157542385a1d342101feb51cf7b8cf76e9441376f1f522a"
}
