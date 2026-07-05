import "hash"

rule sentinel_904613f59987b5ebbc3e7d94b1390420 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "904613f59987b5ebbc3e7d94b1390420"
}
