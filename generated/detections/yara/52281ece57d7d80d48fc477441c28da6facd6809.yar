import "hash"

rule sentinel_52281ece57d7d80d48fc477441c28da6facd6809 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "52281ece57d7d80d48fc477441c28da6facd6809"
}
