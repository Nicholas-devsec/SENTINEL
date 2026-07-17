import "hash"

rule sentinel_77cecf5e2a622ae07d8ae9913457ab57 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "77cecf5e2a622ae07d8ae9913457ab57"
}
