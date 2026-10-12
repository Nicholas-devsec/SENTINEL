import "hash"

rule sentinel_20f0a401676292d4ae34932e61f34afa97bcfc47ee517cda2afeb7222264a193 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "elastic_security_labs"
  condition:
    hash.sha256(0, filesize) == "20f0a401676292d4ae34932e61f34afa97bcfc47ee517cda2afeb7222264a193"
}
