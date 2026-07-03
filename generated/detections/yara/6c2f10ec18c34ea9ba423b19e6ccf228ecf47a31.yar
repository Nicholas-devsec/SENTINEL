import "hash"

rule sentinel_6c2f10ec18c34ea9ba423b19e6ccf228ecf47a31 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha1(0, filesize) == "6c2f10ec18c34ea9ba423b19e6ccf228ecf47a31"
}
