import "hash"

rule sentinel_fc778892bd31ad42e967890ca0d4e2a661897841 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "fc778892bd31ad42e967890ca0d4e2a661897841"
}
