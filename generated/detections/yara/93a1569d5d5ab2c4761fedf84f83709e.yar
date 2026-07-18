import "hash"

rule sentinel_93a1569d5d5ab2c4761fedf84f83709e {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "93a1569d5d5ab2c4761fedf84f83709e"
}
