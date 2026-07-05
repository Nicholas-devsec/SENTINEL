import "hash"

rule sentinel_8b686bac3a44ead6dee49ce4b5a1e5af4a2749d9 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "8b686bac3a44ead6dee49ce4b5a1e5af4a2749d9"
}
