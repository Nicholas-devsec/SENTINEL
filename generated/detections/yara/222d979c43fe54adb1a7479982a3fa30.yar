import "hash"

rule sentinel_222d979c43fe54adb1a7479982a3fa30 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "222d979c43fe54adb1a7479982a3fa30"
}
