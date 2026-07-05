import "hash"

rule sentinel_cb3ac44312acae80a626ba1aa593f4de {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "cb3ac44312acae80a626ba1aa593f4de"
}
