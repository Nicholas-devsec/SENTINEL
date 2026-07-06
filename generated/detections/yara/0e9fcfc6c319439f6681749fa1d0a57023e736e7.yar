import "hash"

rule sentinel_0e9fcfc6c319439f6681749fa1d0a57023e736e7 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "0e9fcfc6c319439f6681749fa1d0a57023e736e7"
}
