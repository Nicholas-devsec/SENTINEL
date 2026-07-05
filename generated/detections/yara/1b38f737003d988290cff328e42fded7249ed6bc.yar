import "hash"

rule sentinel_1b38f737003d988290cff328e42fded7249ed6bc {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "1b38f737003d988290cff328e42fded7249ed6bc"
}
