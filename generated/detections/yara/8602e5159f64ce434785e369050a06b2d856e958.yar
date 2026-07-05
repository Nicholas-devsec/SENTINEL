import "hash"

rule sentinel_8602e5159f64ce434785e369050a06b2d856e958 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "8602e5159f64ce434785e369050a06b2d856e958"
}
