import "hash"

rule sentinel_e373a6356acc578039a720e6a4ad0d9929424f64 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "e373a6356acc578039a720e6a4ad0d9929424f64"
}
