import "hash"

rule sentinel_d13ad6fc5fda54e65f1214e554a5123126ac7b3ce6db57566ed7bd0e92d03d85 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "d13ad6fc5fda54e65f1214e554a5123126ac7b3ce6db57566ed7bd0e92d03d85"
}
