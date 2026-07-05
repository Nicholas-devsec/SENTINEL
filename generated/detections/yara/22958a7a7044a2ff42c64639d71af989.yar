import "hash"

rule sentinel_22958a7a7044a2ff42c64639d71af989 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "22958a7a7044a2ff42c64639d71af989"
}
