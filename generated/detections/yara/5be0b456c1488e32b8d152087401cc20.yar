import "hash"

rule sentinel_5be0b456c1488e32b8d152087401cc20 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "5be0b456c1488e32b8d152087401cc20"
}
