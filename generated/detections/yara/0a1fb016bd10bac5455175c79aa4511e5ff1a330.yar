import "hash"

rule sentinel_0a1fb016bd10bac5455175c79aa4511e5ff1a330 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "discovery:www.group-ib.com"
  condition:
    hash.sha1(0, filesize) == "0a1fb016bd10bac5455175c79aa4511e5ff1a330"
}
