import "hash"

rule sentinel_d284841b717f1ced21ea84cd6a6b6b620daaf7c6f12f8b1f16525ada570f7d82 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "d284841b717f1ced21ea84cd6a6b6b620daaf7c6f12f8b1f16525ada570f7d82"
}
