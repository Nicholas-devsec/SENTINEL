import "hash"

rule sentinel_85767416f8d1e73833ccaa193263d1198857308b3a1185e6f4ebc4164db8584f {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "85767416f8d1e73833ccaa193263d1198857308b3a1185e6f4ebc4164db8584f"
}
