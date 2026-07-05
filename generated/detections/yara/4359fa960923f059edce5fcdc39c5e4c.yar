import "hash"

rule sentinel_4359fa960923f059edce5fcdc39c5e4c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "4359fa960923f059edce5fcdc39c5e4c"
}
