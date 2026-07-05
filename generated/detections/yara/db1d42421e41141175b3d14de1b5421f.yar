import "hash"

rule sentinel_db1d42421e41141175b3d14de1b5421f {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "db1d42421e41141175b3d14de1b5421f"
}
