import "hash"

rule sentinel_7c501632cd3830735040964b69d73a5dc315d0422fe3f1012c4b50db58dc0663 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "7c501632cd3830735040964b69d73a5dc315d0422fe3f1012c4b50db58dc0663"
}
