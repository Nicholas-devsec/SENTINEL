import "hash"

rule sentinel_d452e6814073eff62f07b56d290da680 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "d452e6814073eff62f07b56d290da680"
}
