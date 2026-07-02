import "hash"

rule sentinel_c31217109ba50059d7c081a7e832d0cf {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "c31217109ba50059d7c081a7e832d0cf"
}
