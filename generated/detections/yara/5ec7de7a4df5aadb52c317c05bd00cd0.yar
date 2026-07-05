import "hash"

rule sentinel_5ec7de7a4df5aadb52c317c05bd00cd0 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "5ec7de7a4df5aadb52c317c05bd00cd0"
}
