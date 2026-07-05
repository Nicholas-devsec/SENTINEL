import "hash"

rule sentinel_dd30d0da838bae65d299c3ea9c8fee36edc34837 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "dd30d0da838bae65d299c3ea9c8fee36edc34837"
}
