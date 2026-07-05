import "hash"

rule sentinel_6b45cf0473f25fbb8236e6a96d999f088aa78f60 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "6b45cf0473f25fbb8236e6a96d999f088aa78f60"
}
