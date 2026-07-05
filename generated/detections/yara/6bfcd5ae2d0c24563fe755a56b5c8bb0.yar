import "hash"

rule sentinel_6bfcd5ae2d0c24563fe755a56b5c8bb0 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6bfcd5ae2d0c24563fe755a56b5c8bb0"
}
