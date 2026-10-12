import "hash"

rule sentinel_77c8266935bc040c992ab70abd402bd203b9c12e7548c80b84fd21308c250f0e {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "discovery:gbhackers.com"
  condition:
    hash.sha256(0, filesize) == "77c8266935bc040c992ab70abd402bd203b9c12e7548c80b84fd21308c250f0e"
}
