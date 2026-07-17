import "hash"

rule sentinel_b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:www.microsoft.com"
  condition:
    hash.sha256(0, filesize) == "b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a"
}
