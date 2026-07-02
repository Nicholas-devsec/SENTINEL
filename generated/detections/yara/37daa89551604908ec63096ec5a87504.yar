import "hash"

rule sentinel_37daa89551604908ec63096ec5a87504 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "37daa89551604908ec63096ec5a87504"
}
