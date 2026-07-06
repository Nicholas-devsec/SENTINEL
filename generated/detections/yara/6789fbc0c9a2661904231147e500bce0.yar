import "hash"

rule sentinel_6789fbc0c9a2661904231147e500bce0 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6789fbc0c9a2661904231147e500bce0"
}
