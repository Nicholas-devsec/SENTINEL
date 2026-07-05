import "hash"

rule sentinel_2801386033834bede5f00d5442192cdfd6fe31ce {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "2801386033834bede5f00d5442192cdfd6fe31ce"
}
