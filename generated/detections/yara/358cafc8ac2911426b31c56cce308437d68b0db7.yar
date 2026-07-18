import "hash"

rule sentinel_358cafc8ac2911426b31c56cce308437d68b0db7 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "358cafc8ac2911426b31c56cce308437d68b0db7"
}
