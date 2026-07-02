import "hash"

rule sentinel_944f7a8303225eb154dda8eaf754e7e7 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "944f7a8303225eb154dda8eaf754e7e7"
}
