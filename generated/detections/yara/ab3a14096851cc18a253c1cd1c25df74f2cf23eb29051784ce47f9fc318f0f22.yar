import "hash"

rule sentinel_ab3a14096851cc18a253c1cd1c25df74f2cf23eb29051784ce47f9fc318f0f22 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "ab3a14096851cc18a253c1cd1c25df74f2cf23eb29051784ce47f9fc318f0f22"
}
