import "hash"

rule sentinel_d9617710d4ed8e9b87f6fee0b7014c4101effba0 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "discovery:www.group-ib.com"
  condition:
    hash.sha1(0, filesize) == "d9617710d4ed8e9b87f6fee0b7014c4101effba0"
}
