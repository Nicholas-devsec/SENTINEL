import "hash"

rule sentinel_0a52eca4d42889d0b3d21de101d4bea6 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "0a52eca4d42889d0b3d21de101d4bea6"
}
