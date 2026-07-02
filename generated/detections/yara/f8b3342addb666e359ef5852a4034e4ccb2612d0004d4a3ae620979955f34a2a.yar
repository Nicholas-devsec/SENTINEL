import "hash"

rule sentinel_f8b3342addb666e359ef5852a4034e4ccb2612d0004d4a3ae620979955f34a2a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "f8b3342addb666e359ef5852a4034e4ccb2612d0004d4a3ae620979955f34a2a"
}
