import "hash"

rule sentinel_2adb404eb99fe1b130e326ed36343411 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "2adb404eb99fe1b130e326ed36343411"
}
