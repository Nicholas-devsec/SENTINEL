import "hash"

rule sentinel_22bf76fe317ea6769bd38619bd440e42d119bd6b {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha1(0, filesize) == "22bf76fe317ea6769bd38619bd440e42d119bd6b"
}
