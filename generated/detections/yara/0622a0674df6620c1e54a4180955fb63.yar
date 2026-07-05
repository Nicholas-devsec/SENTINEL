import "hash"

rule sentinel_0622a0674df6620c1e54a4180955fb63 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "0622a0674df6620c1e54a4180955fb63"
}
