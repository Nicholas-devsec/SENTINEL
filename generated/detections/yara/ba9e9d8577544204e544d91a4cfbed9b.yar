import "hash"

rule sentinel_ba9e9d8577544204e544d91a4cfbed9b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ba9e9d8577544204e544d91a4cfbed9b"
}
