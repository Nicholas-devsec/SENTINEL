import "hash"

rule sentinel_c80369f63f57eae5b7574c445093b2f5b1c90c5e {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "c80369f63f57eae5b7574c445093b2f5b1c90c5e"
}
