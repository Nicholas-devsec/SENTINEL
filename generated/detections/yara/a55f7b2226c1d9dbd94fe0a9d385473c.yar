import "hash"

rule sentinel_a55f7b2226c1d9dbd94fe0a9d385473c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "a55f7b2226c1d9dbd94fe0a9d385473c"
}
