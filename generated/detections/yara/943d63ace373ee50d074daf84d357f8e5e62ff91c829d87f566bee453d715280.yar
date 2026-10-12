import "hash"

rule sentinel_943d63ace373ee50d074daf84d357f8e5e62ff91c829d87f566bee453d715280 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "943d63ace373ee50d074daf84d357f8e5e62ff91c829d87f566bee453d715280"
}
