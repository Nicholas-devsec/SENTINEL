import "hash"

rule sentinel_479a7ca02fe77c4465a3cf732eaa4791 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "479a7ca02fe77c4465a3cf732eaa4791"
}
