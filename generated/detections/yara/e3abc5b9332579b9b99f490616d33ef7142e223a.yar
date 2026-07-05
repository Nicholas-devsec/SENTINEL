import "hash"

rule sentinel_e3abc5b9332579b9b99f490616d33ef7142e223a {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "e3abc5b9332579b9b99f490616d33ef7142e223a"
}
