import "hash"

rule sentinel_8de53e5218a9fb8e332209778920471c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "8de53e5218a9fb8e332209778920471c"
}
