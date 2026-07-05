import "hash"

rule sentinel_bdab673b0e619e58212c9e8820d37d51 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "bdab673b0e619e58212c9e8820d37d51"
}
