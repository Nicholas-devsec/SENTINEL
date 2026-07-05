import "hash"

rule sentinel_6bedd45f963b7f078071bb6eeb1edcae {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6bedd45f963b7f078071bb6eeb1edcae"
}
