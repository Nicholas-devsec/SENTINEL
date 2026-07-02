import "hash"

rule sentinel_25968d28095d12ae3084b9675223d6785506f318 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "25968d28095d12ae3084b9675223d6785506f318"
}
