import "hash"

rule sentinel_9d4c5dc5e3e3fda1a041e655a539b8d6 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "9d4c5dc5e3e3fda1a041e655a539b8d6"
}
