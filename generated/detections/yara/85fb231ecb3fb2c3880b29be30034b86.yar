import "hash"

rule sentinel_85fb231ecb3fb2c3880b29be30034b86 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "85fb231ecb3fb2c3880b29be30034b86"
}
