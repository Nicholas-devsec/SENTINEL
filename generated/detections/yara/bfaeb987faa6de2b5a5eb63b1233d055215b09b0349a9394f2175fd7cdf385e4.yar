import "hash"

rule sentinel_bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha256(0, filesize) == "bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4"
}
