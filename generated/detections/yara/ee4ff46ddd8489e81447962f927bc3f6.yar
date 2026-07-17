import "hash"

rule sentinel_ee4ff46ddd8489e81447962f927bc3f6 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "ee4ff46ddd8489e81447962f927bc3f6"
}
