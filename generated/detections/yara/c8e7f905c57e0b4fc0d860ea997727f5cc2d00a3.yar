import "hash"

rule sentinel_c8e7f905c57e0b4fc0d860ea997727f5cc2d00a3 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "c8e7f905c57e0b4fc0d860ea997727f5cc2d00a3"
}
