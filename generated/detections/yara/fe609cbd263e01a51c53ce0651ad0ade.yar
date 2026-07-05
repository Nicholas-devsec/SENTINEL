import "hash"

rule sentinel_fe609cbd263e01a51c53ce0651ad0ade {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "fe609cbd263e01a51c53ce0651ad0ade"
}
