import "hash"

rule sentinel_2fc970e25570532f9cbe33b7ebfe1f0383a7341a {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "discovery:www.group-ib.com"
  condition:
    hash.sha1(0, filesize) == "2fc970e25570532f9cbe33b7ebfe1f0383a7341a"
}
