import "hash"

rule sentinel_c2a26a388bbbf3ee700b938de066838b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "c2a26a388bbbf3ee700b938de066838b"
}
