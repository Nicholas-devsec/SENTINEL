import "hash"

rule sentinel_561a13e7c71a8ebd4db51d04e61ba1ab {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "561a13e7c71a8ebd4db51d04e61ba1ab"
}
