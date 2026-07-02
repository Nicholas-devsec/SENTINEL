import "hash"

rule sentinel_e72df84ddba88ad37b79af285a619b7698914cfa {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "e72df84ddba88ad37b79af285a619b7698914cfa"
}
