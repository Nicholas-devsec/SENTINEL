import "hash"

rule sentinel_cacae2128226e58ba93a2c09b4caaa82 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "cacae2128226e58ba93a2c09b4caaa82"
}
