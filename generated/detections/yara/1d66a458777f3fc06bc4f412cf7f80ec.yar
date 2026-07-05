import "hash"

rule sentinel_1d66a458777f3fc06bc4f412cf7f80ec {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1d66a458777f3fc06bc4f412cf7f80ec"
}
