import "hash"

rule sentinel_dc62e645589463a61e6ac562d034a9de4ed897714389eb6b87bb02f0bd59d565 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "dc62e645589463a61e6ac562d034a9de4ed897714389eb6b87bb02f0bd59d565"
}
