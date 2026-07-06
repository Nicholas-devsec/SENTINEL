import "hash"

rule sentinel_bc673bbff3aa61ea4f719aa3630020f6033d9133 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "bc673bbff3aa61ea4f719aa3630020f6033d9133"
}
