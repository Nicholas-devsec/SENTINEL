import "hash"

rule sentinel_7efc7341472dc671779c0ca8d4e8ac5c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "otx"
  condition:
    hash.md5(0, filesize) == "7efc7341472dc671779c0ca8d4e8ac5c"
}
