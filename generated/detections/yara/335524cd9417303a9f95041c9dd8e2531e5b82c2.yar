import "hash"

rule sentinel_335524cd9417303a9f95041c9dd8e2531e5b82c2 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "335524cd9417303a9f95041c9dd8e2531e5b82c2"
}
