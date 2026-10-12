import "hash"

rule sentinel_711c0aa8cde078aa349fb329e3e44e4272ea66a5e651ad8a64893c76a725c859 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "711c0aa8cde078aa349fb329e3e44e4272ea66a5e651ad8a64893c76a725c859"
}
