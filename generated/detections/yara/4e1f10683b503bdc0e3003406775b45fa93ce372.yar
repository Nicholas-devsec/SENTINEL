import "hash"

rule sentinel_4e1f10683b503bdc0e3003406775b45fa93ce372 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "4e1f10683b503bdc0e3003406775b45fa93ce372"
}
