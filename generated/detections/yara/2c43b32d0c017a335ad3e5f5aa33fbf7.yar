import "hash"

rule sentinel_2c43b32d0c017a335ad3e5f5aa33fbf7 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "2c43b32d0c017a335ad3e5f5aa33fbf7"
}
