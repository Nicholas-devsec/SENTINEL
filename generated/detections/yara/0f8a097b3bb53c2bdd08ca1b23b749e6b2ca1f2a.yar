import "hash"

rule sentinel_0f8a097b3bb53c2bdd08ca1b23b749e6b2ca1f2a {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "0f8a097b3bb53c2bdd08ca1b23b749e6b2ca1f2a"
}
