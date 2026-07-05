import "hash"

rule sentinel_715d011c170ae2246bc17e33de4fbb7d {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "715d011c170ae2246bc17e33de4fbb7d"
}
