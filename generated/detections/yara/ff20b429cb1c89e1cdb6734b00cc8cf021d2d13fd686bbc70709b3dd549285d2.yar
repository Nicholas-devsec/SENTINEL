import "hash"

rule sentinel_ff20b429cb1c89e1cdb6734b00cc8cf021d2d13fd686bbc70709b3dd549285d2 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "ff20b429cb1c89e1cdb6734b00cc8cf021d2d13fd686bbc70709b3dd549285d2"
}
