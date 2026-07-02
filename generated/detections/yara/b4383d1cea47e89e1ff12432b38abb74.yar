import "hash"

rule sentinel_b4383d1cea47e89e1ff12432b38abb74 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "b4383d1cea47e89e1ff12432b38abb74"
}
