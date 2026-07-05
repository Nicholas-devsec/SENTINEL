import "hash"

rule sentinel_bd950dd35df99a4cef5f7056f9338103 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "bd950dd35df99a4cef5f7056f9338103"
}
