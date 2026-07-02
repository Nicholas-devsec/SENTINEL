import "hash"

rule sentinel_b6e04175797eadb9a9b9e07bd4b9066b1ec1aebb {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "b6e04175797eadb9a9b9e07bd4b9066b1ec1aebb"
}
