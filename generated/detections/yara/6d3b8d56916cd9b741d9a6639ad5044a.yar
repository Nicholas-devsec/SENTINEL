import "hash"

rule sentinel_6d3b8d56916cd9b741d9a6639ad5044a {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6d3b8d56916cd9b741d9a6639ad5044a"
}
