import "hash"

rule sentinel_06ab1af35ab18f2b8e8777b397a2cd4b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "06ab1af35ab18f2b8e8777b397a2cd4b"
}
