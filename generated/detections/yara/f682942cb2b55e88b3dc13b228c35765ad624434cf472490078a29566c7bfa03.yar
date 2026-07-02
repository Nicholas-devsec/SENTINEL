import "hash"

rule sentinel_f682942cb2b55e88b3dc13b228c35765ad624434cf472490078a29566c7bfa03 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "f682942cb2b55e88b3dc13b228c35765ad624434cf472490078a29566c7bfa03"
}
