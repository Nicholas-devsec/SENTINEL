import "hash"

rule sentinel_21d7da7df67ca557739367e12f015061 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "21d7da7df67ca557739367e12f015061"
}
