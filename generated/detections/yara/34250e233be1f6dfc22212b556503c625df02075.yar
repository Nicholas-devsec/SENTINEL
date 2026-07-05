import "hash"

rule sentinel_34250e233be1f6dfc22212b556503c625df02075 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "34250e233be1f6dfc22212b556503c625df02075"
}
