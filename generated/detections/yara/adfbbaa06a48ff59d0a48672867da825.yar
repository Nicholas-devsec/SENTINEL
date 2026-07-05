import "hash"

rule sentinel_adfbbaa06a48ff59d0a48672867da825 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "adfbbaa06a48ff59d0a48672867da825"
}
