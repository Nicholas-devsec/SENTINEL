import "hash"

rule sentinel_77c96f339974b65ae435313a8fcc3b35 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "77c96f339974b65ae435313a8fcc3b35"
}
