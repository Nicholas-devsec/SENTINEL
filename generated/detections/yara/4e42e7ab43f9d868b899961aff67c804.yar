import "hash"

rule sentinel_4e42e7ab43f9d868b899961aff67c804 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "4e42e7ab43f9d868b899961aff67c804"
}
