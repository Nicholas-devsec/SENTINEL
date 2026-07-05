import "hash"

rule sentinel_78d5bbac805b333ec066c1a407403077 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "78d5bbac805b333ec066c1a407403077"
}
