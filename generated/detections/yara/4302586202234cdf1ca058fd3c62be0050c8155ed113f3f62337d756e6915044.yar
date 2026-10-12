import "hash"

rule sentinel_4302586202234cdf1ca058fd3c62be0050c8155ed113f3f62337d756e6915044 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "4302586202234cdf1ca058fd3c62be0050c8155ed113f3f62337d756e6915044"
}
