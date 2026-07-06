import "hash"

rule sentinel_e96154e835a8655af64ae2d7ce1256cf {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "e96154e835a8655af64ae2d7ce1256cf"
}
