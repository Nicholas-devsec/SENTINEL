import "hash"

rule sentinel_c5ec7e2ad924e832e49fbac9d0c82719b570e080 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "c5ec7e2ad924e832e49fbac9d0c82719b570e080"
}
