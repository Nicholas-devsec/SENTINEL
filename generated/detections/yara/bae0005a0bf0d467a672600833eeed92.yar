import "hash"

rule sentinel_bae0005a0bf0d467a672600833eeed92 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "otx"
  condition:
    hash.md5(0, filesize) == "bae0005a0bf0d467a672600833eeed92"
}
