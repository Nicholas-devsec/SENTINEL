import "hash"

rule sentinel_4ef616fe7054594e771868ae860feee5 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "4ef616fe7054594e771868ae860feee5"
}
