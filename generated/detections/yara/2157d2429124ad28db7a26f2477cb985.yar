import "hash"

rule sentinel_2157d2429124ad28db7a26f2477cb985 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "2157d2429124ad28db7a26f2477cb985"
}
