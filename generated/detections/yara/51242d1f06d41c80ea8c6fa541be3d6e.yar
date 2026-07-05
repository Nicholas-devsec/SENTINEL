import "hash"

rule sentinel_51242d1f06d41c80ea8c6fa541be3d6e {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "51242d1f06d41c80ea8c6fa541be3d6e"
}
