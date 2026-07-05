import "hash"

rule sentinel_6bbf04841f5907661a1d85a386a256ec {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6bbf04841f5907661a1d85a386a256ec"
}
