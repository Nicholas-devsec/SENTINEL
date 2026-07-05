import "hash"

rule sentinel_7d31b4d8fa391abaf49bf2c36d33fea2 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "7d31b4d8fa391abaf49bf2c36d33fea2"
}
