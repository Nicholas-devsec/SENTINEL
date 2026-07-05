import "hash"

rule sentinel_5757ec1b749b551d3a5e59985327cb34b372bbba {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "5757ec1b749b551d3a5e59985327cb34b372bbba"
}
