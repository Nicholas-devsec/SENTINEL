import "hash"

rule sentinel_7c407c1bad69c37f2498b3efce43d9ce {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "7c407c1bad69c37f2498b3efce43d9ce"
}
