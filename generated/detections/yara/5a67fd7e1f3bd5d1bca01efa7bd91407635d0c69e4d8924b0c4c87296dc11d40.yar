import "hash"

rule sentinel_5a67fd7e1f3bd5d1bca01efa7bd91407635d0c69e4d8924b0c4c87296dc11d40 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "5a67fd7e1f3bd5d1bca01efa7bd91407635d0c69e4d8924b0c4c87296dc11d40"
}
