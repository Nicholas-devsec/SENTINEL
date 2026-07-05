import "hash"

rule sentinel_d772282592444d6215d3a334c7cc338f {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "d772282592444d6215d3a334c7cc338f"
}
