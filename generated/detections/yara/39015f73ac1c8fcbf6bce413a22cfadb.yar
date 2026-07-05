import "hash"

rule sentinel_39015f73ac1c8fcbf6bce413a22cfadb {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "39015f73ac1c8fcbf6bce413a22cfadb"
}
