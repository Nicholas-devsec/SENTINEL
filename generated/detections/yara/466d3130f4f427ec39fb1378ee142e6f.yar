import "hash"

rule sentinel_466d3130f4f427ec39fb1378ee142e6f {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "466d3130f4f427ec39fb1378ee142e6f"
}
