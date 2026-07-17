import "hash"

rule sentinel_41c938b3cd7e55d4077e34976929b140 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "41c938b3cd7e55d4077e34976929b140"
}
