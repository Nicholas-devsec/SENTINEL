import "hash"

rule sentinel_3dec0c4966559f2471c4c03dad2b3d4d {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "3dec0c4966559f2471c4c03dad2b3d4d"
}
