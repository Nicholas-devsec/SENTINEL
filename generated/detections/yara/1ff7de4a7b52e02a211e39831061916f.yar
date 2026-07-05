import "hash"

rule sentinel_1ff7de4a7b52e02a211e39831061916f {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1ff7de4a7b52e02a211e39831061916f"
}
