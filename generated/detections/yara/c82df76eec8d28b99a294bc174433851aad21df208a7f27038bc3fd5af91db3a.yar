import "hash"

rule sentinel_c82df76eec8d28b99a294bc174433851aad21df208a7f27038bc3fd5af91db3a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "c82df76eec8d28b99a294bc174433851aad21df208a7f27038bc3fd5af91db3a"
}
