import "hash"

rule sentinel_67135468d9b43e9a87f9d2f33ef9e361 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "67135468d9b43e9a87f9d2f33ef9e361"
}
