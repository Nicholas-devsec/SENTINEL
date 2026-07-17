import "hash"

rule sentinel_3d2b43f91f65bfbf36a9c71b6b418876 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "3d2b43f91f65bfbf36a9c71b6b418876"
}
