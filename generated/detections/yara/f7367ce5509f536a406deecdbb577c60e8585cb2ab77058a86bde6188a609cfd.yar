import "hash"

rule sentinel_f7367ce5509f536a406deecdbb577c60e8585cb2ab77058a86bde6188a609cfd {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha256(0, filesize) == "f7367ce5509f536a406deecdbb577c60e8585cb2ab77058a86bde6188a609cfd"
}
