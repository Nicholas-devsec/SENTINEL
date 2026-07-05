import "hash"

rule sentinel_8ee45671a9bfc0c4f45c228cdb8a0bbb70898303739a2b787a1ec47ecffb9805 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "8ee45671a9bfc0c4f45c228cdb8a0bbb70898303739a2b787a1ec47ecffb9805"
}
