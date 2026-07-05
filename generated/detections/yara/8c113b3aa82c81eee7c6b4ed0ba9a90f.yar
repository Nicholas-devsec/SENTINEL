import "hash"

rule sentinel_8c113b3aa82c81eee7c6b4ed0ba9a90f {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "8c113b3aa82c81eee7c6b4ed0ba9a90f"
}
