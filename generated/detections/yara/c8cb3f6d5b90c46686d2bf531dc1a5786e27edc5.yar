import "hash"

rule sentinel_c8cb3f6d5b90c46686d2bf531dc1a5786e27edc5 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha1(0, filesize) == "c8cb3f6d5b90c46686d2bf531dc1a5786e27edc5"
}
