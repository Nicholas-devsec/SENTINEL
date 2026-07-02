import "hash"

rule sentinel_3f264a65feeeea6e03914ff97896b134 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "3f264a65feeeea6e03914ff97896b134"
}
