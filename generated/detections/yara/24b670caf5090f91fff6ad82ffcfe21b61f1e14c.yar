import "hash"

rule sentinel_24b670caf5090f91fff6ad82ffcfe21b61f1e14c {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "24b670caf5090f91fff6ad82ffcfe21b61f1e14c"
}
