import "hash"

rule sentinel_4a47fe8302615af0e44cb9340b497562 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "4a47fe8302615af0e44cb9340b497562"
}
