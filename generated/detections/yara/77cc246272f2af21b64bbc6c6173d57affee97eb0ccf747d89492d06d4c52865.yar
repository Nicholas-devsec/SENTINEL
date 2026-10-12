import "hash"

rule sentinel_77cc246272f2af21b64bbc6c6173d57affee97eb0ccf747d89492d06d4c52865 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "discovery:gbhackers.com"
  condition:
    hash.sha256(0, filesize) == "77cc246272f2af21b64bbc6c6173d57affee97eb0ccf747d89492d06d4c52865"
}
