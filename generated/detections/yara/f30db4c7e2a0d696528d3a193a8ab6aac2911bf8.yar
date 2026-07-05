import "hash"

rule sentinel_f30db4c7e2a0d696528d3a193a8ab6aac2911bf8 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "f30db4c7e2a0d696528d3a193a8ab6aac2911bf8"
}
