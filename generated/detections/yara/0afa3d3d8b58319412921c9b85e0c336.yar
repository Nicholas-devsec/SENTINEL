import "hash"

rule sentinel_0afa3d3d8b58319412921c9b85e0c336 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "0afa3d3d8b58319412921c9b85e0c336"
}
