import "hash"

rule sentinel_98006c884a359668964ba2fa91770f35 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "98006c884a359668964ba2fa91770f35"
}
