import "hash"

rule sentinel_5c372345876f52e89d82daa10a778ea6674c7a61 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "5c372345876f52e89d82daa10a778ea6674c7a61"
}
