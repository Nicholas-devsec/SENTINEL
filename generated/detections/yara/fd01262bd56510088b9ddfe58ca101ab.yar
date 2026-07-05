import "hash"

rule sentinel_fd01262bd56510088b9ddfe58ca101ab {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "discovery:arcticwolf.com"
  condition:
    hash.md5(0, filesize) == "fd01262bd56510088b9ddfe58ca101ab"
}
