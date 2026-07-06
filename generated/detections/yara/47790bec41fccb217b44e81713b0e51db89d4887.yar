import "hash"

rule sentinel_47790bec41fccb217b44e81713b0e51db89d4887 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "47790bec41fccb217b44e81713b0e51db89d4887"
}
