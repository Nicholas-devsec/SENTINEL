import "hash"

rule sentinel_fba9a25e345f2ea309398c8e6b7b4105f1143cd2 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "fba9a25e345f2ea309398c8e6b7b4105f1143cd2"
}
