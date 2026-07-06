import "hash"

rule sentinel_f07826cd8101059cbab00ca5244d70d7 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "f07826cd8101059cbab00ca5244d70d7"
}
