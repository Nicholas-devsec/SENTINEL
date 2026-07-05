import "hash"

rule sentinel_82db12c13a8c6695c43ae207fa358ebf {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "82db12c13a8c6695c43ae207fa358ebf"
}
