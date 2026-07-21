import "hash"

rule sentinel_e6c6fa32da47d9341b778bfa424abb4c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "otx"
  condition:
    hash.md5(0, filesize) == "e6c6fa32da47d9341b778bfa424abb4c"
}
