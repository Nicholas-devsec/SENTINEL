import "hash"

rule sentinel_725bf8595f4373bff566ab35a9a6c5d2 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "725bf8595f4373bff566ab35a9a6c5d2"
}
