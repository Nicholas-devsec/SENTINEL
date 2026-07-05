import "hash"

rule sentinel_4650900dca211c00a744bf0c331e6098081b33c1 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "4650900dca211c00a744bf0c331e6098081b33c1"
}
