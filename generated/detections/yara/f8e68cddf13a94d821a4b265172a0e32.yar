import "hash"

rule sentinel_f8e68cddf13a94d821a4b265172a0e32 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "f8e68cddf13a94d821a4b265172a0e32"
}
