import "hash"

rule sentinel_42a760b15fea7c9af718ee45386c1c3ea1bec9e30c95d16c287bcc8b2efdc72e {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "elastic_security_labs"
  condition:
    hash.sha256(0, filesize) == "42a760b15fea7c9af718ee45386c1c3ea1bec9e30c95d16c287bcc8b2efdc72e"
}
