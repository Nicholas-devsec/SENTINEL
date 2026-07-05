import "hash"

rule sentinel_acd8bb66be0920b8bfacaeb22d10ba31 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "acd8bb66be0920b8bfacaeb22d10ba31"
}
