import "hash"

rule sentinel_f61219176469a9f98818c223a40ab36e {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "f61219176469a9f98818c223a40ab36e"
}
