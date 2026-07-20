import "hash"

rule sentinel_5a8031f3c9ff3c65ebaa0aa60f9e59feba83c71c {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "5a8031f3c9ff3c65ebaa0aa60f9e59feba83c71c"
}
