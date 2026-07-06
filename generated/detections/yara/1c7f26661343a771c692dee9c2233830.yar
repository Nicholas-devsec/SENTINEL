import "hash"

rule sentinel_1c7f26661343a771c692dee9c2233830 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1c7f26661343a771c692dee9c2233830"
}
