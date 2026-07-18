import "hash"

rule sentinel_16a4a7b5a478ce3dd732b318f7dfadbd337ab51d804a0a261623ea941417fd5f {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "16a4a7b5a478ce3dd732b318f7dfadbd337ab51d804a0a261623ea941417fd5f"
}
