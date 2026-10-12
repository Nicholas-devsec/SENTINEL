import "hash"

rule sentinel_d910e08a11a4f6f764e7495f4602a00b6024ca6e1b70fe30ba3752b881574365 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "d910e08a11a4f6f764e7495f4602a00b6024ca6e1b70fe30ba3752b881574365"
}
