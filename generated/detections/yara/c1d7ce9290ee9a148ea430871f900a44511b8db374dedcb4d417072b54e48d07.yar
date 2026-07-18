import "hash"

rule sentinel_c1d7ce9290ee9a148ea430871f900a44511b8db374dedcb4d417072b54e48d07 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "c1d7ce9290ee9a148ea430871f900a44511b8db374dedcb4d417072b54e48d07"
}
