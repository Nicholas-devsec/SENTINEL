import "hash"

rule sentinel_1e07711bb5efbdfcf3565f86fee55095 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1e07711bb5efbdfcf3565f86fee55095"
}
