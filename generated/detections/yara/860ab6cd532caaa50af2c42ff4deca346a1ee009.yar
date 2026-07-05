import "hash"

rule sentinel_860ab6cd532caaa50af2c42ff4deca346a1ee009 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "860ab6cd532caaa50af2c42ff4deca346a1ee009"
}
