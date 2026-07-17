import "hash"

rule sentinel_b67aa4f598c0ea625a7409ea7884e10a7bc9c3ff {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "discovery:www.group-ib.com"
  condition:
    hash.sha1(0, filesize) == "b67aa4f598c0ea625a7409ea7884e10a7bc9c3ff"
}
