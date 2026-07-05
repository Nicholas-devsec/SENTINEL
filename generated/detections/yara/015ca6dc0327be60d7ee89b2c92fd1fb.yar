import "hash"

rule sentinel_015ca6dc0327be60d7ee89b2c92fd1fb {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "015ca6dc0327be60d7ee89b2c92fd1fb"
}
