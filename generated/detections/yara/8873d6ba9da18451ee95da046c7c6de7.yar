import "hash"

rule sentinel_8873d6ba9da18451ee95da046c7c6de7 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "8873d6ba9da18451ee95da046c7c6de7"
}
