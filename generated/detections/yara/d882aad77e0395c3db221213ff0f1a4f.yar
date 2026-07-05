import "hash"

rule sentinel_d882aad77e0395c3db221213ff0f1a4f {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "d882aad77e0395c3db221213ff0f1a4f"
}
