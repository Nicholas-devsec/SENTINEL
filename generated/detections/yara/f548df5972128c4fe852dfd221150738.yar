import "hash"

rule sentinel_f548df5972128c4fe852dfd221150738 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "f548df5972128c4fe852dfd221150738"
}
