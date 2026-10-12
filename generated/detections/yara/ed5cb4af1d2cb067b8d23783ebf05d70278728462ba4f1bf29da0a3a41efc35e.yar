import "hash"

rule sentinel_ed5cb4af1d2cb067b8d23783ebf05d70278728462ba4f1bf29da0a3a41efc35e {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "elastic_security_labs"
  condition:
    hash.sha256(0, filesize) == "ed5cb4af1d2cb067b8d23783ebf05d70278728462ba4f1bf29da0a3a41efc35e"
}
