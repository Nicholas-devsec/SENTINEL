import "hash"

rule sentinel_e8b18c420669deb8fc6f69e74146e499057c3c77436ac6ca54af37befa9ddaa5 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "e8b18c420669deb8fc6f69e74146e499057c3c77436ac6ca54af37befa9ddaa5"
}
