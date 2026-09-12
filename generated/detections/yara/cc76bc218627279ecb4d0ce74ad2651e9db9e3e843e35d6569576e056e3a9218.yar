import "hash"

rule sentinel_cc76bc218627279ecb4d0ce74ad2651e9db9e3e843e35d6569576e056e3a9218 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cyberpress.org"
  condition:
    hash.sha256(0, filesize) == "cc76bc218627279ecb4d0ce74ad2651e9db9e3e843e35d6569576e056e3a9218"
}
