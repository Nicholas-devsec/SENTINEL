import "hash"

rule sentinel_918dd413cceed3b8aeaa79e45d9d7b2030d73e2affa4339b8f9d043d08844f62 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "918dd413cceed3b8aeaa79e45d9d7b2030d73e2affa4339b8f9d043d08844f62"
}
