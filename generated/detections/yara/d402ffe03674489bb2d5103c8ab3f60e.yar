import "hash"

rule sentinel_d402ffe03674489bb2d5103c8ab3f60e {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "d402ffe03674489bb2d5103c8ab3f60e"
}
