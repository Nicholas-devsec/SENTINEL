import "hash"

rule sentinel_683852647171ca0de9a0b1f32833f4ec {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "683852647171ca0de9a0b1f32833f4ec"
}
