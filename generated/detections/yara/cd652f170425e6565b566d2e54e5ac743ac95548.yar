import "hash"

rule sentinel_cd652f170425e6565b566d2e54e5ac743ac95548 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "cd652f170425e6565b566d2e54e5ac743ac95548"
}
