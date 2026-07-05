import "hash"

rule sentinel_70735b4870e7d8e52bf45548df922149 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "70735b4870e7d8e52bf45548df922149"
}
