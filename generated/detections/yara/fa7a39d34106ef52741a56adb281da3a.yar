import "hash"

rule sentinel_fa7a39d34106ef52741a56adb281da3a {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "fa7a39d34106ef52741a56adb281da3a"
}
