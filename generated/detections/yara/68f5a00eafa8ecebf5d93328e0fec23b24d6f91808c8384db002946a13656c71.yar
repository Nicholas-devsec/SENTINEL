import "hash"

rule sentinel_68f5a00eafa8ecebf5d93328e0fec23b24d6f91808c8384db002946a13656c71 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "elastic_security_labs"
  condition:
    hash.sha256(0, filesize) == "68f5a00eafa8ecebf5d93328e0fec23b24d6f91808c8384db002946a13656c71"
}
