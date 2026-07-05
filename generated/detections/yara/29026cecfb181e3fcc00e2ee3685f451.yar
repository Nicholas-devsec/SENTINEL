import "hash"

rule sentinel_29026cecfb181e3fcc00e2ee3685f451 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "29026cecfb181e3fcc00e2ee3685f451"
}
