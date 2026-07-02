import "hash"

rule sentinel_5377fbbbb068fc5119a04bbf4e73c835ef46604a {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "5377fbbbb068fc5119a04bbf4e73c835ef46604a"
}
