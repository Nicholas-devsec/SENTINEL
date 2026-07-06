import "hash"

rule sentinel_45e25f810c84427f1c778d42a6cd1f6d796917ae {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "45e25f810c84427f1c778d42a6cd1f6d796917ae"
}
