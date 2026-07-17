import "hash"

rule sentinel_dc506ff7bb72735444fb3703a6bee6d8 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "gbhackers_blog"
  condition:
    hash.md5(0, filesize) == "dc506ff7bb72735444fb3703a6bee6d8"
}
