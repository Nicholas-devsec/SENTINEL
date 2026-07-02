import "hash"

rule sentinel_133517cc137dba1e885871e6d461717b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "133517cc137dba1e885871e6d461717b"
}
