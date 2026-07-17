import "hash"

rule sentinel_8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:www.microsoft.com"
  condition:
    hash.sha256(0, filesize) == "8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c"
}
