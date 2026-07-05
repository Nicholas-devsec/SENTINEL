import "hash"

rule sentinel_9a7af0a766f7717d478c94414b15d25e {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "9a7af0a766f7717d478c94414b15d25e"
}
