import "hash"

rule sentinel_64622cb996b115fac71477650db0bb90 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "64622cb996b115fac71477650db0bb90"
}
