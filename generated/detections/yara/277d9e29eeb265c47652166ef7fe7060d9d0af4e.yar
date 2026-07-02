import "hash"

rule sentinel_277d9e29eeb265c47652166ef7fe7060d9d0af4e {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "277d9e29eeb265c47652166ef7fe7060d9d0af4e"
}
