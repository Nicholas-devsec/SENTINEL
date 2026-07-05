import "hash"

rule sentinel_100f2629b705497eaf152730ac3b41bc {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "100f2629b705497eaf152730ac3b41bc"
}
