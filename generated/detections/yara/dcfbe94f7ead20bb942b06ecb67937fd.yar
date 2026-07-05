import "hash"

rule sentinel_dcfbe94f7ead20bb942b06ecb67937fd {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "dcfbe94f7ead20bb942b06ecb67937fd"
}
