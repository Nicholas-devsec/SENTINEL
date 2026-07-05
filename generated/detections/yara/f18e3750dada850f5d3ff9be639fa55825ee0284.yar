import "hash"

rule sentinel_f18e3750dada850f5d3ff9be639fa55825ee0284 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "f18e3750dada850f5d3ff9be639fa55825ee0284"
}
