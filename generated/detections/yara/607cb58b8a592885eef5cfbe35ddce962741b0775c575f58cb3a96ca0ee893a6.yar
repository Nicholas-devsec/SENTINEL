import "hash"

rule sentinel_607cb58b8a592885eef5cfbe35ddce962741b0775c575f58cb3a96ca0ee893a6 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "607cb58b8a592885eef5cfbe35ddce962741b0775c575f58cb3a96ca0ee893a6"
}
