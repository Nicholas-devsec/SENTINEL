import "hash"

rule sentinel_6f237ca43382d389421a084b18e0e32b522d60a10727d4742c9822ad64c9d999 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "6f237ca43382d389421a084b18e0e32b522d60a10727d4742c9822ad64c9d999"
}
