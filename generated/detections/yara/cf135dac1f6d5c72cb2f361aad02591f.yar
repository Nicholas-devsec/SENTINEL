import "hash"

rule sentinel_cf135dac1f6d5c72cb2f361aad02591f {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "cf135dac1f6d5c72cb2f361aad02591f"
}
