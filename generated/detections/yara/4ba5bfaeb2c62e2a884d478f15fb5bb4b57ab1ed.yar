import "hash"

rule sentinel_4ba5bfaeb2c62e2a884d478f15fb5bb4b57ab1ed {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "4ba5bfaeb2c62e2a884d478f15fb5bb4b57ab1ed"
}
