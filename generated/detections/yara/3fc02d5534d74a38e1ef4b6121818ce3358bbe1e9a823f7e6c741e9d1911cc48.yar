import "hash"

rule sentinel_3fc02d5534d74a38e1ef4b6121818ce3358bbe1e9a823f7e6c741e9d1911cc48 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "3fc02d5534d74a38e1ef4b6121818ce3358bbe1e9a823f7e6c741e9d1911cc48"
}
