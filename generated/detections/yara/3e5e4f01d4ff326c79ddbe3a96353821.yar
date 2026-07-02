import "hash"

rule sentinel_3e5e4f01d4ff326c79ddbe3a96353821 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "3e5e4f01d4ff326c79ddbe3a96353821"
}
