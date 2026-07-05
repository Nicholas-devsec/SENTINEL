import "hash"

rule sentinel_1c302704a76e2effc99f2d5e339d7f64 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1c302704a76e2effc99f2d5e339d7f64"
}
