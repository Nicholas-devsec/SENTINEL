import "hash"

rule sentinel_144cc3e02b7ef259abcb2d6eaf5f4f770630ad2c75dcfa48437df3b17f5094bf {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "144cc3e02b7ef259abcb2d6eaf5f4f770630ad2c75dcfa48437df3b17f5094bf"
}
