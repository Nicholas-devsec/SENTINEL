import "hash"

rule sentinel_9212fe6f148538c752ed95789c963e3b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "9212fe6f148538c752ed95789c963e3b"
}
