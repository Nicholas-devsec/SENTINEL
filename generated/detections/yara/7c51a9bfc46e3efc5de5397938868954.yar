import "hash"

rule sentinel_7c51a9bfc46e3efc5de5397938868954 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "7c51a9bfc46e3efc5de5397938868954"
}
