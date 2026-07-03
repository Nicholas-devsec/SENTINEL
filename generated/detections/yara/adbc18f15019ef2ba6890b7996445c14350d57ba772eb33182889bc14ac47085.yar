import "hash"

rule sentinel_adbc18f15019ef2ba6890b7996445c14350d57ba772eb33182889bc14ac47085 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "adbc18f15019ef2ba6890b7996445c14350d57ba772eb33182889bc14ac47085"
}
