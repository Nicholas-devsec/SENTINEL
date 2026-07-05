import "hash"

rule sentinel_e1b2d22e59ae44fc34f2120f1b86c7f8 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "e1b2d22e59ae44fc34f2120f1b86c7f8"
}
