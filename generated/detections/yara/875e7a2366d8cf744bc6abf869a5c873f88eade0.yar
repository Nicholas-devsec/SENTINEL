import "hash"

rule sentinel_875e7a2366d8cf744bc6abf869a5c873f88eade0 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "875e7a2366d8cf744bc6abf869a5c873f88eade0"
}
