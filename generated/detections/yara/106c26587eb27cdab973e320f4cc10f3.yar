import "hash"

rule sentinel_106c26587eb27cdab973e320f4cc10f3 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "106c26587eb27cdab973e320f4cc10f3"
}
