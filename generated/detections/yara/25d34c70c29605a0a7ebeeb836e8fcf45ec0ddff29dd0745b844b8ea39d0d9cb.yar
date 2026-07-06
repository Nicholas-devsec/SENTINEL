import "hash"

rule sentinel_25d34c70c29605a0a7ebeeb836e8fcf45ec0ddff29dd0745b844b8ea39d0d9cb {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "25d34c70c29605a0a7ebeeb836e8fcf45ec0ddff29dd0745b844b8ea39d0d9cb"
}
