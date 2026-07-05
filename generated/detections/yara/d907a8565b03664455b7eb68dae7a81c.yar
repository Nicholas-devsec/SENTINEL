import "hash"

rule sentinel_d907a8565b03664455b7eb68dae7a81c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "d907a8565b03664455b7eb68dae7a81c"
}
