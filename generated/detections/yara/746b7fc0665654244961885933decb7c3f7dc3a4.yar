import "hash"

rule sentinel_746b7fc0665654244961885933decb7c3f7dc3a4 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "746b7fc0665654244961885933decb7c3f7dc3a4"
}
