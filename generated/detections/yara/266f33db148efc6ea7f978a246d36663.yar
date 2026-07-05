import "hash"

rule sentinel_266f33db148efc6ea7f978a246d36663 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "266f33db148efc6ea7f978a246d36663"
}
