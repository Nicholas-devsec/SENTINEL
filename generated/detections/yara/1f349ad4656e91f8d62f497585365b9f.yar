import "hash"

rule sentinel_1f349ad4656e91f8d62f497585365b9f {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1f349ad4656e91f8d62f497585365b9f"
}
