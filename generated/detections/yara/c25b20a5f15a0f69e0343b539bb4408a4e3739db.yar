import "hash"

rule sentinel_c25b20a5f15a0f69e0343b539bb4408a4e3739db {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "c25b20a5f15a0f69e0343b539bb4408a4e3739db"
}
