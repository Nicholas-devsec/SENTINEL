import "hash"

rule sentinel_b98575f3c0259b480a31b917aa73bc56 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "discovery:arcticwolf.com"
  condition:
    hash.md5(0, filesize) == "b98575f3c0259b480a31b917aa73bc56"
}
