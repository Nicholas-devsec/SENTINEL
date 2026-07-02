import "hash"

rule sentinel_873522d113b0a23fe25ed2b723e1c7274d93c87e {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "873522d113b0a23fe25ed2b723e1c7274d93c87e"
}
