import "hash"

rule sentinel_d1f41d50627a69e02d4f7464beb2f8b8 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "d1f41d50627a69e02d4f7464beb2f8b8"
}
