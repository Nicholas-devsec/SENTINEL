import "hash"

rule sentinel_5d11d7b9b175695c197014bc6aa2fbdb {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "5d11d7b9b175695c197014bc6aa2fbdb"
}
