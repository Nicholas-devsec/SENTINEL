import "hash"

rule sentinel_6cb178572fe453a83472a18a6b112a33 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6cb178572fe453a83472a18a6b112a33"
}
