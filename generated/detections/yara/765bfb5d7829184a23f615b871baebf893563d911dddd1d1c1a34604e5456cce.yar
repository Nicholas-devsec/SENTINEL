import "hash"

rule sentinel_765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce"
}
