import "hash"

rule sentinel_5291f0767ba9c4b4810611aceb26bb594ee19779 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "5291f0767ba9c4b4810611aceb26bb594ee19779"
}
