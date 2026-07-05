import "hash"

rule sentinel_a8e9db0011ac6886b75ddcd69bc503d8 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "a8e9db0011ac6886b75ddcd69bc503d8"
}
