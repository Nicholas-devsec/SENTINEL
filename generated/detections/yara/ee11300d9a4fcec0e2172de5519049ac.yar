import "hash"

rule sentinel_ee11300d9a4fcec0e2172de5519049ac {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ee11300d9a4fcec0e2172de5519049ac"
}
