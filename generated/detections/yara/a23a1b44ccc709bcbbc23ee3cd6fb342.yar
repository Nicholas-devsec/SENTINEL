import "hash"

rule sentinel_a23a1b44ccc709bcbbc23ee3cd6fb342 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "a23a1b44ccc709bcbbc23ee3cd6fb342"
}
