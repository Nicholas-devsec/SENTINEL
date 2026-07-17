import "hash"

rule sentinel_8dda05168ea8610a2449419a47517bc32823d6ec {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "discovery:www.group-ib.com"
  condition:
    hash.sha1(0, filesize) == "8dda05168ea8610a2449419a47517bc32823d6ec"
}
