import "hash"

rule sentinel_c725815cbb07ab5be8903e74ef8aea46ef9c25e4a3bc626ae94bfc1ae21df6e3 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "c725815cbb07ab5be8903e74ef8aea46ef9c25e4a3bc626ae94bfc1ae21df6e3"
}
