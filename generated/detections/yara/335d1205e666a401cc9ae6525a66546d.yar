import "hash"

rule sentinel_335d1205e666a401cc9ae6525a66546d {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "335d1205e666a401cc9ae6525a66546d"
}
