import "hash"

rule sentinel_549bb011a726e68223260f0bb50f7920 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "549bb011a726e68223260f0bb50f7920"
}
