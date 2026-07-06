import "hash"

rule sentinel_dc45f63319b41252b02079c0d1cf70cb58153cfd {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "dc45f63319b41252b02079c0d1cf70cb58153cfd"
}
