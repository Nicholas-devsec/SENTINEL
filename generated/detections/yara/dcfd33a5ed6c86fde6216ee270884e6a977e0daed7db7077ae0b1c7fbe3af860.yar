import "hash"

rule sentinel_dcfd33a5ed6c86fde6216ee270884e6a977e0daed7db7077ae0b1c7fbe3af860 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "dcfd33a5ed6c86fde6216ee270884e6a977e0daed7db7077ae0b1c7fbe3af860"
}
