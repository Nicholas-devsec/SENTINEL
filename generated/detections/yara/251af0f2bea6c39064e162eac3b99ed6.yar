import "hash"

rule sentinel_251af0f2bea6c39064e162eac3b99ed6 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "251af0f2bea6c39064e162eac3b99ed6"
}
