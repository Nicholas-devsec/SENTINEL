import "hash"

rule sentinel_6e6bd2f7566ffa52d52fa9d5f048bbb9246d3d50110c6b0c248919ad796c6fd4 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "6e6bd2f7566ffa52d52fa9d5f048bbb9246d3d50110c6b0c248919ad796c6fd4"
}
