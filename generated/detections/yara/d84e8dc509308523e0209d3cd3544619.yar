import "hash"

rule sentinel_d84e8dc509308523e0209d3cd3544619 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "d84e8dc509308523e0209d3cd3544619"
}
