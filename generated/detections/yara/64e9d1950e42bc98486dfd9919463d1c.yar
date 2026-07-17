import "hash"

rule sentinel_64e9d1950e42bc98486dfd9919463d1c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "gbhackers_blog"
  condition:
    hash.md5(0, filesize) == "64e9d1950e42bc98486dfd9919463d1c"
}
