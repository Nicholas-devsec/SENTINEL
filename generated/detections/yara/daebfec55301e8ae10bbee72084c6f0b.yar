import "hash"

rule sentinel_daebfec55301e8ae10bbee72084c6f0b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "daebfec55301e8ae10bbee72084c6f0b"
}
