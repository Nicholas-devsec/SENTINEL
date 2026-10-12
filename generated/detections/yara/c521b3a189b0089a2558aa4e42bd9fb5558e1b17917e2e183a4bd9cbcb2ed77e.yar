import "hash"

rule sentinel_c521b3a189b0089a2558aa4e42bd9fb5558e1b17917e2e183a4bd9cbcb2ed77e {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "c521b3a189b0089a2558aa4e42bd9fb5558e1b17917e2e183a4bd9cbcb2ed77e"
}
