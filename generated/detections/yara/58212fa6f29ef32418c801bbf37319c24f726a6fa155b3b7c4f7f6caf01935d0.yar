import "hash"

rule sentinel_58212fa6f29ef32418c801bbf37319c24f726a6fa155b3b7c4f7f6caf01935d0 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "58212fa6f29ef32418c801bbf37319c24f726a6fa155b3b7c4f7f6caf01935d0"
}
