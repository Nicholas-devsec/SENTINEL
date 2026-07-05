import "hash"

rule sentinel_be5b469852253e4c60925777c114b46e7fca797bd21dc39b2f3774589ce0909a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "be5b469852253e4c60925777c114b46e7fca797bd21dc39b2f3774589ce0909a"
}
