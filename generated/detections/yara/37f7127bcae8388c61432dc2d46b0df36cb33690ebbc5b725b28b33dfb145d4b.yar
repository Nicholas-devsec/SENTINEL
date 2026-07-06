import "hash"

rule sentinel_37f7127bcae8388c61432dc2d46b0df36cb33690ebbc5b725b28b33dfb145d4b {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "37f7127bcae8388c61432dc2d46b0df36cb33690ebbc5b725b28b33dfb145d4b"
}
