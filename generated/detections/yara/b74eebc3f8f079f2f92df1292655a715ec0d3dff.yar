import "hash"

rule sentinel_b74eebc3f8f079f2f92df1292655a715ec0d3dff {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "b74eebc3f8f079f2f92df1292655a715ec0d3dff"
}
