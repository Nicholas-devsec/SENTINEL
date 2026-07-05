import "hash"

rule sentinel_3e27e51227c7d613c967afbff8e7e6af {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "3e27e51227c7d613c967afbff8e7e6af"
}
