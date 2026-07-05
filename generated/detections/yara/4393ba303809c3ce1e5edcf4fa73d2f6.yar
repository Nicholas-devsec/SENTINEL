import "hash"

rule sentinel_4393ba303809c3ce1e5edcf4fa73d2f6 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "4393ba303809c3ce1e5edcf4fa73d2f6"
}
