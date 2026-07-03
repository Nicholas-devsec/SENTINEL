import "hash"

rule sentinel_ca7f5c0668f1a871523d485e42884c3b98910117d7ca17c8b3c3b3744a936e0f {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "ca7f5c0668f1a871523d485e42884c3b98910117d7ca17c8b3c3b3744a936e0f"
}
