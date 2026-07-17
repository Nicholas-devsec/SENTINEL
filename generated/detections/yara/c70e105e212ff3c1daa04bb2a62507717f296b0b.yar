import "hash"

rule sentinel_c70e105e212ff3c1daa04bb2a62507717f296b0b {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha1(0, filesize) == "c70e105e212ff3c1daa04bb2a62507717f296b0b"
}
