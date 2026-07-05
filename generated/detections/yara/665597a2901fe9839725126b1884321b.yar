import "hash"

rule sentinel_665597a2901fe9839725126b1884321b {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "665597a2901fe9839725126b1884321b"
}
