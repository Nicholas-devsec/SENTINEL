import "hash"

rule sentinel_006510ce1da2b7410376f0788c19e55616eb4bcc30072d25b7d0871dc32aa11c {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "discovery:gbhackers.com"
  condition:
    hash.sha256(0, filesize) == "006510ce1da2b7410376f0788c19e55616eb4bcc30072d25b7d0871dc32aa11c"
}
